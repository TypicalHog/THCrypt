// THCrypt v1.3
// Copyright (c) 2017 TypicalHog
// https://github.com/TypicalHog/THCrypt

// I will comment the code and explain how everything works when I catch some time.

#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <vector>

bool file_exists(const std::string &filename);
void progress_bar(unsigned long long current, unsigned long long max, unsigned long long rate = 100, unsigned long long width = 50);
int generate_key(const std::string &filename_key, const int size);
int generate_lookup_tables(const int seed);
void encrypt(long long id, long long num_threads, long long key_size, unsigned char *key, long long buffer_size, unsigned char *buffer, unsigned char *lookup_table);
void decrypt(long long id, long long num_threads, long long key_size, unsigned char *key, long long buffer_size, unsigned char *buffer, unsigned char *lookup_table);

int main(int argc, char *argv[])
{
	bool external_run;
	std::string operation, filename_lookup_table, filename_key, filename_in, filename_out;
	if (argc == 2)
	{
		external_run = true;
		filename_in = argv[1];
		if (!file_exists(filename_in))
		{
			std::cout << "\nERROR: Cannot find file." << std::endl;
			return 0;
		}
		const long long length = strlen(argv[1]);
		if (argv[1][length - 4] == '.' && argv[1][length - 3] == 'e' && argv[1][length - 2] == 'n' && argv[1][length - 1] == 'c')
		{
			operation = "-d";
			filename_lookup_table = "lookup_table_inverted.bin";
		}
		else
		{
			operation = "-e";
			filename_lookup_table = "lookup_table.bin";
		}

		if (operation == "-e")
		{
			filename_out = filename_in;
			filename_out.append(".enc");
		}
		else
		{
			filename_out = filename_in.substr(0, filename_in.size() - 4);
		}

		filename_key = "key.txt";
		const int new_key_size = 16;
		switch (generate_key(filename_key, new_key_size))
		{
		case 0:
			std::cout << "INFO: Existing key found." << std::endl;
			break;
		case 1:
			std::cout << "INFO: Generated new " << new_key_size * 8 << "-bit key." << std::endl;
			std::cout << "WARNING: Generated key is NOT cryptographically secure!" << std::endl;
			break;
		default:
			std::cout << "ERROR: Cannot create key." << std::endl;
			return 0;
		}
	}
	else if (argc == 5)
	{
		external_run = false;
		operation = argv[1];
		if (operation == "-e")
		{
			filename_lookup_table = "lookup_table.bin";
		}
		else if (operation == "-d")
		{
			filename_lookup_table = "lookup_table_inverted.bin";
		}
		else
		{
			std::cout << "\nERROR: Bad argument." << std::endl;
			std::cout << "Usage: THCrypt <-e | -d> <key filename> <input filename> <output filename>" << std::endl;
			return 0;
		}

		filename_key = argv[2];
		filename_in = argv[3];
		if (!file_exists(filename_key) || !file_exists(filename_in))
		{
			std::cout << "\nERROR: Cannot find file." << std::endl;
			return 0;
		}

		filename_out = argv[4];
	}
	else
	{
		std::cout << "\nERROR: Wrong number of arguments." << std::endl;
		std::cout << "Usage: THCrypt <-e | -d> <key filename> <input filename> <output filename>" << std::endl;
		return 0;
	}

	if (!external_run) std::cout << '\n';
	switch (generate_lookup_tables(1337))
	{
	case 0:
		std::cout << "INFO: Existing lookup tables found." << std::endl;
		break;
	case 1:
		std::cout << "INFO: New lookup tables generated." << std::endl;
		break;
	default:
		std::cout << "ERROR: Cannot create lookup tables." << std::endl;
		return 0;
	}

	std::ifstream f_key(filename_key, std::ios::binary);
	std::ifstream f_in(filename_in, std::ios::binary);
	std::ofstream f_out(filename_out, std::ios::binary);
	std::ifstream f_lookup_table(filename_lookup_table, std::ios::binary);

	if (f_in.is_open() && f_out.is_open() && f_key.is_open() && f_lookup_table.is_open())
	{
		unsigned char key[256];
		unsigned char p_buffer[256 * 256];
		unsigned char s_buffer[256 * 256];
		unsigned char lookup_table[256 * 256];

		long long key_size, file_size, bytes_left, num_chunks;
		const long long buffer_size = 65536LL;

		long long num_threads = std::thread::hardware_concurrency();
		if (num_threads == 0)
		{
			num_threads = 1;
		}
		std::vector<std::thread> threads;

		f_lookup_table.read(reinterpret_cast<char *>(&lookup_table), 256 * 256);
		f_lookup_table.close();

		f_key.seekg(0, std::ios::end);
		key_size = f_key.tellg();
		f_key.seekg(0, std::ios::beg);

		f_in.seekg(0, std::ios::end);
		file_size = f_in.tellg();
		f_in.seekg(0, std::ios::beg);
		num_chunks = (unsigned long long)ceil((double)file_size / (double)buffer_size);

		if (key_size > 256LL)
		{
			std::cout << "WARNING: Key too long, truncating to 256 bytes!" << std::endl;
			key_size = 256LL;
		}
		f_key.read(reinterpret_cast<char *>(&key), key_size);

		if (operation == "-e")
		{
			std::cout << "\nOperation:   Encryption" << std::endl;
		}
		else /*if (operation == "-d")*/
		{
			std::cout << "\nOperation:   Decryption" << std::endl;
		}
		std::cout << "Threads:     " << num_threads << std::endl;
		std::cout << "Key source:  " << "[FILE] " << filename_key << std::endl;
		//std::cout << "Key source:  " << "[USER_INPUT]" << std::endl;
		std::cout << "Key size:    " << key_size << " bytes (" << key_size * 8 << "-bit)" << std::endl;
		std::cout << "Input file:  " << filename_in << std::endl;
		std::cout << "Output file: " << filename_out << std::endl;
		if (file_size < 1024)
		{
			std::cout << "File size:   " << file_size << " bytes" << std::endl;
		}
		else if (file_size < 1024 * 1024)
		{
			std::cout << "File size:   " << file_size / 1024.0 << " KB (" << file_size << " bytes)" << std::endl;
		}
		else if (file_size < 1024 * 1024 * 1024)
		{
			std::cout << "File size:   " << file_size / (1024.0 * 1024.0) << " MB (" << file_size << " bytes)" << std::endl;
		}
		else
		{
			std::cout << "File size:   " << file_size / (1024.0 * 1024.0 * 1024.0) << " GB (" << file_size << " bytes)" << std::endl;
		}
		std::cout << "-------------------------------------------------------------------" << std::endl;

		auto start = std::chrono::high_resolution_clock::now();

		enum BufferStatus { EMPTY = -1, DATA_LOADED = 0, DATA_IN_USE = 1, DATA_PROCESSED = 2 };
		long long p_buffer_status = EMPTY;
		long long s_buffer_status = EMPTY;
		long long p_buffer_size = 0;
		long long s_buffer_size = 0;
		unsigned long long current_chunk = 0;

		bytes_left = file_size;
		if (num_chunks != 0)
		{
			progress_bar(0, num_chunks);
		}
		else
		{
			progress_bar(1, 1);
		}
		while (p_buffer_status != EMPTY || s_buffer_status != EMPTY || bytes_left > 0)
		{
			// Join threads
			for (unsigned long long id = 0; id < threads.size(); ++id) {
				threads[(unsigned int)id].join();
			}
			threads.clear();
			if (p_buffer_status == DATA_IN_USE)
			{
				p_buffer_status = DATA_PROCESSED;
			}
			else if (s_buffer_status == DATA_IN_USE)
			{
				s_buffer_status = DATA_PROCESSED;
			}

			// Create threads
			if (p_buffer_status == DATA_LOADED)
			{
				if (operation == "-e")
				{
					for (long long id = 0; id < num_threads; ++id) {
						threads.push_back(std::thread(encrypt, id, num_threads, key_size, std::ref(key), p_buffer_size, std::ref(p_buffer), std::ref(lookup_table)));
					}
				}
				else /*if (operation == "-d")*/
				{
					for (long long id = 0; id < num_threads; ++id) {
						threads.push_back(std::thread(decrypt, id, num_threads, key_size, std::ref(key), p_buffer_size, std::ref(p_buffer), std::ref(lookup_table)));
					}
				}
				p_buffer_status = DATA_IN_USE;
			}
			else if (s_buffer_status == DATA_LOADED)
			{
				if (operation == "-e")
				{
					for (long long id = 0; id < num_threads; ++id) {
						threads.push_back(std::thread(encrypt, id, num_threads, key_size, std::ref(key), s_buffer_size, std::ref(s_buffer), std::ref(lookup_table)));
					}
				}
				else /*if (operation == "-d")*/
				{
					for (long long id = 0; id < num_threads; ++id) {
						threads.push_back(std::thread(decrypt, id, num_threads, key_size, std::ref(key), s_buffer_size, std::ref(s_buffer), std::ref(lookup_table)));
					}
				}
				s_buffer_status = DATA_IN_USE;
			}

			// Write data
			if (p_buffer_status == DATA_PROCESSED)
			{
				f_out.write(reinterpret_cast<const char *>(&p_buffer), p_buffer_size);
				++current_chunk;
				progress_bar(current_chunk, num_chunks);
				p_buffer_status = EMPTY;
			}
			else if (s_buffer_status == DATA_PROCESSED)
			{
				f_out.write(reinterpret_cast<const char *>(&s_buffer), s_buffer_size);
				++current_chunk;
				progress_bar(current_chunk, num_chunks);
				s_buffer_status = EMPTY;
			}

			// Read data
			if (bytes_left > 0)
			{
				if (p_buffer_status == EMPTY)
				{
					if (bytes_left >= buffer_size)
					{
						f_in.read(reinterpret_cast<char *>(&p_buffer), buffer_size);
						p_buffer_size = buffer_size;
						bytes_left -= buffer_size;
					}
					else
					{
						f_in.read(reinterpret_cast<char *>(&p_buffer), bytes_left);
						p_buffer_size = bytes_left;
						bytes_left = 0;
					}
					p_buffer_status = DATA_LOADED;
				}
				else if (s_buffer_status == EMPTY)
				{
					if (bytes_left >= buffer_size)
					{
						f_in.read(reinterpret_cast<char *>(&s_buffer), buffer_size);
						bytes_left -= buffer_size;
						s_buffer_size = buffer_size;
					}
					else
					{
						f_in.read(reinterpret_cast<char *>(&s_buffer), bytes_left);
						s_buffer_size = bytes_left;
						bytes_left = 0;
					}
					s_buffer_status = DATA_LOADED;
				}
			}
		}

		f_in.close();
		f_out.close();

		auto end = std::chrono::high_resolution_clock::now();
		auto time = std::chrono::duration<double, std::micro>(end - start).count();

		if (time < 1000)
		{
			std::cout << "\nTIME: " << time << " microseconds" << std::endl;
		}
		else if (time < 1000'000)
		{
			time = std::chrono::duration<double, std::milli>(end - start).count();
			std::cout << "\nTIME: " << time << " milliseconds" << std::endl;
		}
		else if (time < 1000'000'000)
		{
			time = std::chrono::duration<double>(end - start).count();
			std::cout << "\nTIME: " << time << " seconds" << std::endl;
		}
		else if (time < 1000'000'000LL * 60)
		{
			time = std::chrono::duration<double, std::ratio<60>>(end - start).count();
			std::cout << "\nTIME: " << time << " minutes" << std::endl;
		}
		else
		{
			time = std::chrono::duration<double, std::ratio<3600>>(end - start).count();
			std::cout << "\nTIME: " << time << " hours" << std::endl;
		}
	}
	else
	{
		std::cout << "\nERROR: Cannot access file." << std::endl;
	}

	std::cout << "\n===COMPLETED===" << std::endl;
	if (external_run) std::cin.ignore();

	return 0;
}

bool file_exists(const std::string &filename)
{
	std::ifstream file(filename.c_str());
	return file.is_open();
}

void progress_bar(unsigned long long current, unsigned long long max, unsigned long long rate, unsigned long long width)
{
	if (max >= rate) if (current % (max / rate) != 0) if (current != max) return;
	//if (current % (max / rate + 1) != 0) if (current != max) return;

	float ratio = (float)current / max;
	unsigned long long c = (unsigned int)(ratio * width);

	std::cout << "\rPROGRESS: " << std::setw(3) << (int)(ratio * 100) << "% [";
	for (unsigned long long i = 0; i < c; ++i) std::cout << "=";
	for (unsigned long long i = c; i < width; ++i) std::cout << " ";
	std::cout << "]" << std::flush;
}

int generate_key(const std::string &filename_key, const int size)
{
	if (!file_exists(filename_key))
	{
		std::ofstream f_key(filename_key, std::ios::binary);

		if (f_key.is_open())
		{
			char *key;
			key = new char[size];

			std::random_device rd;
			std::mt19937 rng(rd());
			std::uniform_int_distribution<int> dist(0, 255);

			for (int i = 0; i < size; ++i)
			{
				key[i] = (unsigned char)dist(rng);
			}

			f_key.write(reinterpret_cast<const char *>(&key), size);
			f_key.close();
			delete[] key;
			return 1;
		}
		else
		{
			return -1;
		}
	}
	return 0;
}

int generate_lookup_tables(const int seed)
{
	if (!file_exists("lookup_table.bin") || !file_exists("lookup_table_inverted.bin"))
	{
		std::ofstream f_lookup_table("lookup_table.bin", std::ios::binary);
		std::ofstream f_lookup_table_inverted("lookup_table_inverted.bin", std::ios::binary);

		if (f_lookup_table.is_open() && f_lookup_table_inverted.is_open())
		{
			unsigned char lookup_table[256 * 256];
			unsigned char lookup_table_inverted[256 * 256];

			std::vector<unsigned char> unused;
			std::mt19937 rng(seed);
			std::uniform_int_distribution<int> dist(0, 255);
			int random_int;

			for (int i = 0; i < 256; ++i)
			{
				for (int j = 0; j < 256; ++j)
				{
					unused.push_back((unsigned char)j);
				}

				for (int j = 0; j < 256; ++j)
				{
					random_int = dist(rng);
					while (random_int >= (int)unused.size())
					{
						random_int = dist(rng);
					}

					lookup_table[(i * 256) + j] = unused[random_int];
					lookup_table_inverted[(i * 256) + unused[random_int]] = (unsigned char)j;
					unused.erase(unused.begin() + random_int);
				}
			}

			f_lookup_table.write(reinterpret_cast<const char *>(&lookup_table), 256 * 256);
			f_lookup_table_inverted.write(reinterpret_cast<const char *>(&lookup_table_inverted), 256 * 256);
			f_lookup_table.close();
			f_lookup_table_inverted.close();
			return 1;
		}
		else
		{
			return -1;
		}
	}
	return 0;
}

void encrypt(long long id, long long num_threads, long long key_size, unsigned char *key, long long buffer_size, unsigned char *buffer, unsigned char *lookup_table)
{
	for (long long i = 0; i < key_size; ++i)
	{
		for (long long j = id; j < buffer_size; j += num_threads)
		{
			buffer[j] = lookup_table[key[i] * 256 + (buffer[j] + j) % 256];
		}
	}
}

void decrypt(long long id, long long num_threads, long long key_size, unsigned char *key, long long buffer_size, unsigned char *buffer, unsigned char *lookup_table)
{
	for (long long i = key_size - 1; i > -1; --i)
	{
		for (long long j = id; j < buffer_size; j += num_threads)
		{
			buffer[j] = (lookup_table[key[i] * 256 + buffer[j]] - j) % 256;
		}
	}
}
