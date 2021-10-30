/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2021 Hercules Dev Team
 *
 * Hercules is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#define HERCULES_CORE

#include "common/atomic.h"
#include "common/cbasetypes.h"
#include "common/core.h"
#include "common/thread.h"
#include "common/rwlock.h"
#include "common/showmsg.h"
#include "common/nullpo.h"
#include "common/utils.h"
#include "common/ers.h"
#include "common/memmgr.h"
#include "common/timer.h"
#include "common/mutex.h"
#include "common/db.h"

#define XXH_STATIC_LINKING_ONLY
#include "test/test_db/xxhash.h"

#include "test/test_entry.h"

#include <stdio.h>
#include <stdlib.h>


//
// DB unit testing
//


struct s_dictionary_info {
	char word[127];
	size_t len;
};
VECTOR_STRUCT_DECL(s_dictionary_vector, struct s_dictionary_info);
struct s_dictionary_vector dictionary_vector = VECTOR_STATIC_INITIALIZER;

/**
 * Frees allocated data in db_unit_init (must be last test)
 **/
bool db_unit_final(void *not_used) {
	VECTOR_CLEAR(dictionary_vector);
	return true;
}


struct s_csv_data {
	char collumn_name[32];

	void *ptr; // Pointer to object
	enum {T_UINT32, T_FLOAT, T_DOUBLE, T_STRING} type;
	size_t offset; // Field offset in pointer
	size_t length; // Length of field
	size_t obj_size; // Length of object
	/**
	 * Should ptr be treated as an array of <code>entry_count</code> length?
	 * @see csv_new
	 **/
	bool is_array;
};
#define SIZEOF_MEMBER(type, member) sizeof(((type *)0)->member)
// Members of struct
#define CSV_DECL(_name, _ptr, _type, _obj, _field, _array) \
	{(_name), (_ptr), (_type), offsetof(_obj, _field), SIZEOF_MEMBER(_obj,_field), sizeof(_obj), (_array)}
// "Pure" arrays
#define CSV_DECL_ARR(_name, _ptr, _type) \
	{(_name), (_ptr), (_type), 0, 0, sizeof(*_ptr), true}

/**
 * Creates a new CSV file with provided data
 * @param filepath File path
 * @param csv Collumn information
 * @param csv_length Number of collumns
 * @param entry_count Number of entries in this file
 * @param ignore_header When set the header is not printed
 * @see s_csv_data
 **/
bool csv_new(const char *filepath, struct s_csv_data *csv, size_t csv_length, int entry_count, bool ignore_header) {
	bool retval = false;
	char *buffer = NULL;
	// Estimate maximum buffer length
	size_t header_len = csv_length*sizeof(csv->collumn_name);
	size_t line_len = 0;
	for(int i = 0; i < csv_length; i++) {
		line_len += (csv[i].type == T_STRING)?csv[i].length:127;
	}
	size_t buffer_len = header_len + line_len * entry_count;
	assert(buffer_len);
	buffer = aMalloc(buffer_len);

	size_t pos = 0;
	if(!ignore_header) {
		for(int i = 0; i < csv_length; i++) {
			pos += sprintf(&buffer[pos],
				"%s,", csv[i].collumn_name);
		}
		buffer[pos-1] = '\n';
	}

#define MEMBER_FROM_OFFSET(csv_idx, var_idx) \
	((unsigned char*)csv[(csv_idx)].ptr+((var_idx)*csv[(csv_idx)].obj_size)+csv[(csv_idx)].offset)
	for(int i = 0; i < entry_count; i++) {
		for(int j = 0; j < csv_length; j++) {
			size_t idx = (csv[j].is_array)?i:0;
			switch(csv[j].type) {
				case T_STRING:
					pos += snprintf(&buffer[pos], 127,
						"\"%s\"", (const char*)MEMBER_FROM_OFFSET(j, idx));
					break;
				case T_FLOAT:
				{
					float flt_value = *(float*)MEMBER_FROM_OFFSET(j, idx);
					pos += snprintf(&buffer[pos], 127,
						"%f", flt_value);
					break;
				}
				case T_DOUBLE:
				{
					double dflt_value = *(double*)MEMBER_FROM_OFFSET(j, idx);
					pos += snprintf(&buffer[pos], 127,
						"%lf", dflt_value);
					break;
				}
				case T_UINT32:
				{
					uint32_t int_value = *(uint32_t*)MEMBER_FROM_OFFSET(j, idx);
					pos += snprintf(&buffer[pos], 127,
						"%ld", int_value);
					break;
				}
				default:
					ShowWarning("db_unit_csv: Unknown field type %d (entry %d, name %s)\n",
						csv[j].type, j, csv[j].collumn_name);
					break;
			}
			buffer[pos++] = ',';
		}
		buffer[pos-1] = '\n';
	}
#undef MEMBER_FROM_OFFSET
	// Open file and flush buffer
	FILE *fp = fopen(filepath, "a");
	if(!fp) {
		ShowError("csv_new: Failed to open file: '%s'\n",
			strerror(errno));
		goto cleanup;
	}
	if(!fwrite(buffer, pos, 1, fp)) {
		ShowWarning("csv_new: Failed to write to '%s'\n",
			filepath);
		goto cleanup;
	}
	retval = true;
	// Fall-through
cleanup:
	if(buffer)
		aFree(buffer);
	if(fp)
		fclose(fp);
	return retval;
}
// @see db_unit_strkey_performance
struct s_strkey_test {
	float load_factor;
	uint32_t initial_capacity;
	char name[32];
	double result;
	uint32_t iteration_count;
};
// @see db_unit_strkey_performance
struct s_strkey_unit_result {
	char name[127];
	const struct s_hash_functions *hash_data; //< [In]  Hash function to be tested
	struct s_strkey_test *out_test;     //< [Out] aMalloc array of test data
	size_t test_count;
};

/**
 * Hash functions used in testing
 * @see db_unit_hash_performance
 **/
struct s_hash_functions {
	DBHasher hash;
	char name[32];
};
// @see db_unit_hash_performance
struct s_strkey_hash_result {
	const struct s_hash_functions *hash_data; //< Not to be freed
	double *result;                           //< [Out] aMalloc array of test data
	size_t result_count;                      //< Length of result (and hash_data)
	int iteration_count;                      //< Iteration count
};

struct s_result_data {
	struct s_strkey_unit_result *strkey_result;
	size_t strkey_result_count;

	struct s_strkey_hash_result *hash_result;
};
/**
 * Generates CSV from test data and then frees allocated memory.
 **/
bool db_unit_csv(void *data) {
	struct s_result_data *result = data;

	for(int i = 0; i < result->strkey_result_count; i++) {
		struct s_strkey_unit_result *strkey = &result->strkey_result[i];
		struct s_csv_data csv_db[] = {
			CSV_DECL("Name", strkey, T_STRING, struct s_strkey_unit_result, name, false),
			CSV_DECL("Hash", strkey->hash_data, T_STRING, struct s_hash_functions, name, false),
			CSV_DECL("Load factor", strkey->out_test, T_FLOAT, struct s_strkey_test, load_factor, true),
			CSV_DECL("Initial capacity", strkey->out_test, T_UINT32, struct s_strkey_test, initial_capacity, true),
			CSV_DECL("Iteration", strkey->out_test, T_UINT32, struct s_strkey_test, iteration_count, true),
			CSV_DECL("Result (ms)", strkey->out_test, T_DOUBLE, struct s_strkey_test, result, true),
		};
		csv_new("db_hash_comparison.csv", csv_db, sizeof(csv_db)/sizeof(*csv_db), strkey->test_count,
			(i != 0));
	}

	struct s_strkey_hash_result *hash = result->hash_result;
	struct s_csv_data csv_hash[] = {
		CSV_DECL("Name", hash->hash_data, T_STRING, struct s_hash_functions, name, true),
		CSV_DECL("Iteration count", hash, T_UINT32, struct s_strkey_hash_result, iteration_count, false),
		CSV_DECL_ARR("Result (ms)", hash->result, T_DOUBLE),
	};
	csv_new("hash_comparison.csv", csv_hash, sizeof(csv_hash)/sizeof(*csv_hash), hash->result_count, false);

	for(int i = 0; i < result->strkey_result_count; i++)
		aFree(result->strkey_result[i].out_test);
	aFree(result->strkey_result);

	aFree(hash->result);
	aFree(hash);

	aFree(result);
	return true;
}
#undef CSV_DECL
#undef SIZEOF_MEMBER

static uint64 unit_db_string_hash_athena(const struct DBKey_s *key)
{
	const char *k = key->u.str;
	unsigned int hash = 0;
	unsigned short i;

	for (i = 0; *k; ++i) {
		hash = (hash*33 + ((unsigned char)*k))^(hash>>24);
		k++;
		if (i == key->len)
			break;
	}

	return (uint64)hash;
}

/**
 * MurmurHash2
 * 
 * @author Austin Appleby (public domain)
 * @see github.com/aappleby/smhasher
 **/
uint64 unit_db_string_hash_murmur2(const struct DBKey_s *key)
{
	// 'm' and 'r' are mixing constants generated offline.
	// They're not really 'magic', they just happen to work well.
	const uint32_t m = 0x5bd1e995;
	const int r = 24;

	// Initialize the hash to a 'random' value
	uint32_t h = 1234 ^ key->len;
	int16_t maxlen = key->len;

	// Mix 4 bytes at a time into the hash
	const unsigned char * data = key->u.str;

	while(maxlen >= 4) {
		uint32_t k = *(uint32_t*)data;

		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		maxlen -= 4;
	}

	// Handle the last few bytes of the input array
	switch(maxlen)
	{
		case 3: h ^= data[2] << 16;
		case 2: h ^= data[1] << 8;
		case 1: h ^= data[0];
			h *= m;
	};

	// Do a few final mixes of the hash to ensure the last few
	// bytes are well-incorporated.
	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}

/**
 * MurmurHash3
 *
 * @author Austin Appleby (public domain)
 * @see github.com/aappleby/smhasher
 **/
uint64 db_string_hash_murmur3(const struct DBKey_s *key)
{
#ifdef _MSC_VER
#define ROTL32(x, r) _rotl((x),(r))
#else
#define ROTL32(x, r) ( ((x)<<(r)) | ((x)>>(-(r)&31)) )
#endif
	const uint8_t * data = (const uint8_t*)key->u.str;
	const int nblocks = key->len / 4;

	uint32_t h1 = 1234; // seed

	const uint32_t c1 = 0xcc9e2d51;
	const uint32_t c2 = 0x1b873593;

	//----------
	// body

	const uint32_t * blocks = (const uint32_t *)(data + nblocks*4);

	for(int i = -nblocks; i; i++)
	{
		uint32_t k1 = blocks[i];

		k1 *= c1;
		k1 = ROTL32(k1,15);
		k1 *= c2;

		h1 ^= k1;
		h1 = ROTL32(h1,13); 
		h1 = h1*5+0xe6546b64;
	}

	//----------
	// tail

	const uint8_t * tail = (const uint8_t*)(data + nblocks*4);

	uint32_t k1 = 0;

	switch(key->len & 3)
	{
		case 3: k1 ^= tail[2] << 16;
		case 2: k1 ^= tail[1] << 8;
		case 1: k1 ^= tail[0];
				k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
	};

	//----------
	// finalization

	h1 ^= key->len;
	h1 ^= h1 >> 16;
	h1 *= 0x85ebca6b;
	h1 ^= h1 >> 13;
	h1 *= 0xc2b2ae35;
	h1 ^= h1 >> 16;

	return h1;
#undef ROTL32
}

/**
 * MurmurHash3 128bit x64
 *
 * @author Austin Appleby (public domain)
 * @see github.com/aappleby/smhasher
 **/
uint64 db_string_hash_murmur3_128(const struct DBKey_s *key)
{
#ifdef _MSC_VER
#define ROTL64(x, r) _rotl64((x),(r))
#define BIG_CONSTANT(x) (x)
#else
#define ROTL64(x, r) ( ((x) << (r)) | ((x) >> (64 - (r))) )
#define BIG_CONSTANT(x) (x##LLU)
#endif
	const uint8_t * data = (const uint8_t*)key->u.str;
	const int nblocks = key->len / 16;

	uint64_t h1 = 1234;
	uint64_t h2 = 1234;//seed

	const uint64_t c1 = BIG_CONSTANT(0x87c37b91114253d5);
	const uint64_t c2 = BIG_CONSTANT(0x4cf5ad432745937f);

	//----------
	// body

	const uint64_t * blocks = (const uint64_t *)(data);

	for(int i = 0; i < nblocks; i++)
	{
		uint64_t k1 = blocks[i*2+0];
		uint64_t k2 = blocks[i*2+1];

		k1 *= c1; k1  = ROTL64(k1,31); k1 *= c2; h1 ^= k1;

		h1 = ROTL64(h1,27); h1 += h2; h1 = h1*5+0x52dce729;

		k2 *= c2; k2  = ROTL64(k2,33); k2 *= c1; h2 ^= k2;

		h2 = ROTL64(h2,31); h2 += h1; h2 = h2*5+0x38495ab5;
	}
	
	//----------
	// tail
	
	const uint8_t * tail = (const uint8_t*)(data + nblocks*16);
	
	uint64_t k1 = 0;
	uint64_t k2 = 0;
	
	switch(key->len & 15)
	{
		case 15: k2 ^= ((uint64_t)tail[14]) << 48;
		case 14: k2 ^= ((uint64_t)tail[13]) << 40;
		case 13: k2 ^= ((uint64_t)tail[12]) << 32;
		case 12: k2 ^= ((uint64_t)tail[11]) << 24;
		case 11: k2 ^= ((uint64_t)tail[10]) << 16;
		case 10: k2 ^= ((uint64_t)tail[ 9]) << 8;
		case  9: k2 ^= ((uint64_t)tail[ 8]) << 0;
				k2 *= c2; k2  = ROTL64(k2,33); k2 *= c1; h2 ^= k2;

		case  8: k1 ^= ((uint64_t)tail[ 7]) << 56;
		case  7: k1 ^= ((uint64_t)tail[ 6]) << 48;
		case  6: k1 ^= ((uint64_t)tail[ 5]) << 40;
		case  5: k1 ^= ((uint64_t)tail[ 4]) << 32;
		case  4: k1 ^= ((uint64_t)tail[ 3]) << 24;
		case  3: k1 ^= ((uint64_t)tail[ 2]) << 16;
		case  2: k1 ^= ((uint64_t)tail[ 1]) << 8;
		case  1: k1 ^= ((uint64_t)tail[ 0]) << 0;
				k1 *= c1; k1  = ROTL64(k1,31); k1 *= c2; h1 ^= k1;
	};

	//----------
	// finalization

	h1 ^= key->len; h2 ^= key->len;

	h1 += h2;
	h2 += h1;

#define FMIX64(_fm)                               \
	do {                                          \
		(_fm) ^= (_fm) >> 33;                     \
		(_fm) *= BIG_CONSTANT(0xff51afd7ed558ccd);\
		(_fm) ^= (_fm) >> 33;                     \
		(_fm) *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);\
		(_fm) ^= (_fm) >> 33;                     \
	} while(false)

	FMIX64(h1);
	FMIX64(h2);

	h1 += h2;
	h2 += h1;

	return h1;
	//((uint64_t*)out)[0] = h1;
	//((uint64_t*)out)[1] = h2;
#undef FMIX64
#undef ROTL64
#undef BIG_CONSTANT
}

uint64 db_string_hash_xxhash32(const struct DBKey_s *key)
{
	uint32_t h = XXH32(key->u.str, key->len, 1234);
	return h;
}

uint64 db_string_hash_xxhash64(const struct DBKey_s *key)
{
	uint64_t h = XXH64(key->u.str, key->len, 1234);
	return h;
}

uint64 db_string_hash_xxh364(const struct DBKey_s *key)
{
	uint64_t h = XXH3_64bits(key->u.str, key->len);
	return h;
}

/**
 * Hashes all dictionary_vector for iterator_count times
 * @return Time for a total dictionary_vector hash (ms)
 * @see db_unit_strkey_performance
 **/
double db_unit_strkey_do_hash(DBHasher hash, const char *name, int iteration_count)
{
	struct s_dictionary_info *info = VECTOR_DATA(dictionary_vector);
	int64 tick_begin, tick_end, tick_total;
	ShowMessage("%s begin:\n", name);

	tick_begin = timer->gettick_nocache();
	for(int i = 0; i < iteration_count; i++) {
		for(int j = 0; j < VECTOR_LENGTH(dictionary_vector); j++) {
			struct DBKey_s key = DB->str2key(info[j].word, info[j].len);
			hash(&key);
			//hash(&(struct DBKey_s){.u.str = info[j].word, .len = info[j].len});
		}
	}
	tick_end = timer->gettick_nocache();
	tick_total = tick_end-tick_begin;
	double time = (double)tick_total/iteration_count;
	ShowMessage("%s end (%lf ms)\n", name, time);
	return time;
}


/**
 * Hash function suite
 * @see db_unit_hash_performance
 * @see db_unit_strkey_performance
 **/
struct s_hash_functions hash_suite[] = {
	{unit_db_string_hash_athena,  "Athena 32"},
	{unit_db_string_hash_murmur2, "Murmur2 32"},
	{db_string_hash_murmur3, "Murmur3 32"},
	{db_string_hash_murmur3_128, "Murmur3 x64 128"},
	{db_string_hash_xxhash32, "XXHASH 32"},
	{db_string_hash_xxhash64, "XXHASH 64"},
	{db_string_hash_xxh364, "XXH3 64"},
};

/**
 * Compares performance of different hash types against loaded dictionary
 * @param result_obj Empty s_strkey_hash_result object
 **/
bool db_unit_hash_performance(void *result_obj) {
	struct s_strkey_hash_result *result = result_obj;
#ifdef DEBUG
	ShowDebug("db_unit_hash_performance: DEBUG flag set, tests won't represent "
		"real performance differences!\n");
#endif
	result->hash_data = hash_suite;
	result->result_count = sizeof(hash_suite)/sizeof(*hash_suite);
	result->result = aMalloc(sizeof(*result->result)*result->result_count);
	result->iteration_count = 100;
	for(int i = 0; i < result->result_count; i++) {
		result->result[i] =  db_unit_strkey_do_hash(hash_suite[i].hash,
							                hash_suite[i].name,
			                                result->iteration_count);
	}
	return true;
}

/**
 * Performs insertion and retrieval operations with all entries in
 * dictionary vector.
 * @return Average time for all operations
 * @retval 0.f There were errors while testing
 **/
double db_unit_strkey_do(int iteration_count,
	float load_factor, uint32_t capacity, const char *name,
	DBHasher hash) {
	struct s_dictionary_info *info = VECTOR_DATA(dictionary_vector);
	struct DBMap *strdb = DB->alloc(__FILE__, __func__, __LINE__,
		DB_STRING, DB_OPT_BASE|DB_OPT_DISABLE_LOCK, 0, capacity, load_factor);
	// Change to READ_LOCK to force the system to use CAS lock
	db_lock(strdb, WRITE_LOCK/*READ_LOCK*/);
	int error_count = 0;
	int64_t tick_begin, tick_end, tick_total;
	ShowMessage("Performance type:\t%s\n"
		        "Load factor:     \t%f\n"
		        "Initial capacity:\t%ld\n"
		        "Expected peak:   \t%ld\n"
		        "Iteration count: \t%ld\n",
		        name, load_factor, capacity,
		        VECTOR_LENGTH(dictionary_vector),
		        iteration_count);

	strdb->set_hash(strdb, hash);
	db_unlock(strdb);

	tick_begin = timer->gettick_nocache();
	for(int j = 0; j < iteration_count; j++) {
		db_lock(strdb, WRITE_LOCK);
		for(int i = 0; i < VECTOR_LENGTH(dictionary_vector); i++) {
			if(!info[i].len)
				continue;
			if(strdb_put(strdb, info[i].word, info[i].len, info[i].word)) {
				// Entry already exists
				ShowError("db_unit_strkey: Duplicated key '%s'\n", info[i].word);
				error_count++;
			}
		}
		db_unlock(strdb);
		db_lock(strdb, READ_LOCK);
		for(int i = 0; i < VECTOR_LENGTH(dictionary_vector); i++) {
			if(!info[i].len)
				continue;
			char *found = strdb_get(strdb, info[i].word, info[i].len);
			if(!found) {
				ShowError("db_unit_str_key: Failed to find key '%s'\n", info[i].word);
				error_count++;
				continue;
			}
			if(strcmp(found, info[i].word)) {
				ShowError("db_unit_str_key: Key '%s' with data mismatch ('%s')\n",
					info[i].word, found);
				error_count++;
			}
		}

		db_clear(strdb);
		db_unlock(strdb);
	} // iteration_count
	tick_end = timer->gettick_nocache();
	tick_total = tick_end-tick_begin;
	double time = (double)tick_total/iteration_count;
	ShowMessage("Estimated time:  \t%lfms\n\n", time);
	db_lock(strdb, WRITE_LOCK);
	db_destroy(strdb); // Unlocks
	return (error_count)?0.f:time;
}

/**
 * Tests insertion/retrieval and database rehashing
 * Tests database performance with different types of hash function and other parameters
 * @param result s_strkey_unit_result with hash_data set
 *               out_test should be aFree'd by caller.
 **/
bool db_unit_strkey_performance(void *result) {
	struct s_strkey_unit_result *data = result;
	int iteration_count = 10;
	struct s_strkey_test strkey_suite[] = {
		//{0.f,           HASH_SIZE, "Off"},
		//{LOAD_FACTOR,   HASH_SIZE, "Default"},
		//{logf(2),       HASH_SIZE, "Log(2)"}, // stackoverflow.com/a/31401836
		//{0.5f,          HASH_SIZE, "Half"},
		//{1.f,           HASH_SIZE, "Ideal"},
		{0.f, HASH_SIZE,  "0"},
		{0.1f, HASH_SIZE, "1"},
		{0.2f, HASH_SIZE, "2"},
		{0.3f, HASH_SIZE, "3"},
		{0.4f, HASH_SIZE, "4"},
		{0.5f, HASH_SIZE, "5"},
		{0.6f, HASH_SIZE, "6"},
		{0.7f, HASH_SIZE, "7"},
		{0.8f, HASH_SIZE, "8"},
		{0.9f, HASH_SIZE, "9"},
		{1.f, HASH_SIZE,  "10"},

	};
	data->test_count = sizeof(strkey_suite)/sizeof(*strkey_suite);
	for(int i = 0; i < data->test_count; i++) {
		strkey_suite[i].result = db_unit_strkey_do(iteration_count,
		                                    strkey_suite[i].load_factor,
		                                    strkey_suite[i].initial_capacity,
		                                    strkey_suite[i].name,
		                                    data->hash_data->hash);
		strkey_suite[i].iteration_count = iteration_count;
	}
	data->out_test = aMalloc(sizeof(strkey_suite));
	memcpy(data->out_test, strkey_suite, sizeof(strkey_suite));
	return true;
}

/**
 * Tests insertion/retrieval and database rehashing
 **/
bool db_unit_strkey(void *not_used) {
	double result = 
	db_unit_strkey_do(1, LOAD_FACTOR, HASH_SIZE, "Collision test",
		DB->default_hash(DB_STRING));
	return (result != 0.f);
}

/**
 * Loads test data and sets up clean DB environment
 **/
bool db_unit_init(void *not_used) {
	bool retval = true;
//	DB->final(); // Turn previous instance off
//	DB->init();
	FILE *fp;
	fp = fopen("words.txt"/*"Tutte_le_parole_inglesi_no_dup.txt"*/, "r");
	if(!fp) {
		ShowError("db_unit_init: Failed to open file: '%s'\n",
			strerror(errno));
		return false;
	}
	TEST_ASSERT(fp, "Failed to setup DB unit testing environment!");

	char buffer[2048];
	size_t read_count = 0;
	int buffer_pos = 0;
	VECTOR_ENSURE(dictionary_vector, /*217455*/466555, 1);
	do {
		read_count = fread(&buffer[buffer_pos], 1, sizeof(buffer)-buffer_pos, fp);
		for(size_t i = 0; i < read_count+buffer_pos;) {
			struct s_dictionary_info dic;
			size_t len;
			char *del = strchr(&buffer[i], '\n');
			if(del) {
				*del = '\0';
				len = del - &buffer[i];
			} else {
				len = read_count + buffer_pos - i;
				memcpy(&buffer[0], &buffer[i], len);
				buffer_pos = len;
				break; // Fill next buffer
			}
			strncpy(dic.word, &buffer[i], sizeof(dic.word));
			if(len > sizeof(dic.word)) {
				ShowWarning("db_unit_init: Found word exceeding %ld, count %ld (%s)\n",
					sizeof(dic.word), len, &buffer[i]);
			}
			i += len+1;
			dic.len = len+1;
			VECTOR_ENSURE(dictionary_vector, 1, 100);
			VECTOR_PUSHCOPY(dictionary_vector, dic);
		}
	} while(read_count);
	if(ferror(fp)) {
		ShowError("db_unit_init: Failed to read file\n");
		retval = false;
	}
	fclose(fp);
	return retval;
} 

/**
 * Adds database tests to the provided suite
 **/
struct s_test_suite *test_db_add(struct s_test_suite *test) {
	test = test_add(test, db_unit_init, "DB setup", NULL);
	test = test_add(test, db_unit_strkey, "DB basic functions", NULL);

	size_t hash_suite_len = sizeof(hash_suite)/sizeof(*hash_suite);
	struct s_strkey_unit_result *strkey_unit_result =
		aMalloc(sizeof(*strkey_unit_result)*hash_suite_len);
	for(size_t i = 0; i < hash_suite_len; i++) {
		snprintf(strkey_unit_result[i].name, sizeof(strkey_unit_result[i].name),
			"[%zd] DB Performance (%s)",
			i, hash_suite[i].name);
		strkey_unit_result[i].hash_data = &hash_suite[i];
		test = test_add(test, db_unit_strkey_performance,
			            strkey_unit_result[i].name,
				        &strkey_unit_result[i]);
	}

	struct s_strkey_hash_result *performance_result =
		aCalloc(1, sizeof(*performance_result));
	test = test_add(test, db_unit_hash_performance, "Hash performance", performance_result);

	struct s_result_data *result_final = aMalloc(sizeof(*result_final));
	result_final->strkey_result = strkey_unit_result;
	result_final->strkey_result_count = hash_suite_len;

	result_final->hash_result = performance_result;
	test = test_add(test, db_unit_csv, "CSV", result_final);

	test = test_add(test, db_unit_final, "DB final", NULL);
	return test;
}
