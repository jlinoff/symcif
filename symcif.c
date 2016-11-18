/*
 * C program that demonstrates how to interface to the openssl library
 * to encrypt or decrypt data. You can also list the available ciphers
 * and digests.
 *
 * The name symcif derives loosely from symmetric cipher.
 *
 * It is of no practical use since these functions are already
 * available from the command line openssl tool but it might be useful
 * for learning purposes.
 *
 * I am not sure how to license this. None of the code was taken
 * directly from the openssl source but it has similarities because I
 * read it carefully to understand how to use the system. That is
 * especially true for BIO idioms so I have decided to preserve the
 * license of the original software which is quite reasonable.
 *
 * Copyright 2016 Joe Linoff. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <libgen.h>
#include <time.h>
#include <ctype.h> /* islower() */

#include <openssl/conf.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

/*
 * Run mode.
 */
enum mode_t {NOTSET, ENCRYPT, DECRYPT, LIST};

/*
 * Run options.
 */
struct options_t {
  char* cipher;
  char* digest;
  unsigned int rounds;
  char* salt;
  char* pass;
  char* ifile;
  char* ofile;
  char* base;
  char* version;
  mode_t mode;
  bool base64;
  unsigned int verbose;
};

/*
 * forward reference for help.
 */
void help(const struct options_t* opts);

/*
 * Lifted from crypto/evp/names.c
 */
struct doall_cipher {
    void *arg;
    void (*fn) (const EVP_CIPHER *ciph,
                const char *from, const char *to, void *arg);
};

/*
 * Get time stamp.
 */
const char* get_ts() {
  static char buf[1024];
  time_t t;
  struct tm* tmp;
  t = time(NULL);
  tmp = localtime(&t);
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tmp);
  return buf;
}

/*
 * Print an error message and exit.
 */
#define ERR(fmt, args...) \
  fprintf(stderr, "ERROR:%d %s - ", __LINE__, get_ts()); fprintf(stderr, fmt, ##args); fprintf(stderr, "\n"); exit(1)

/*
 * Print an info message.
 */
#define INFO(fmt, args...) \
  printf( "INFO:%d %s - ", __LINE__, get_ts()); printf( fmt, ##args); printf( "\n")

/*
 * Print a warning message.
 */
#define WARN(fmt, args...) \
  printf( "WARNING:%d %s - ", __LINE__, get_ts()); printf( fmt, ##args); printf( "\n")

/*
 * check to see if any of n args are equal to match..
 */
bool eqn(const char* match, ...) {
  va_list args;
  const char* str;

  va_start(args, match);
  while ((str = va_arg(args, const char*))) {
    if (!strcmp(match, str)) {
      return true;
    }
  }
  va_end(args);

  return false;
}

/*
 * Create a string on the heap.
 */
char* newstr(const char* src) {
  char* dst = NULL;
  if (src != NULL) {
    dst = calloc(1, strlen(src) + 1);
    strcpy(dst, src);
  } else {
    dst = calloc(1, 1);
  }
  return dst;
}

/*
 * Generate random string with n characters using a caller defined character set.
 */
char* gen_random_string(int n, const char* cset) {
  int len = strlen(cset);
  char* s = NULL;
  int i, j;
  if (n > 0) {
    s = calloc(1, n + 1);
    for(i=0; i<n; i++) {
      j = rand() % len;
      s[i] = cset[j];
    }
  }
  return s;
}

/*
 * Generate random string with n characters from the alphanumeric character set.
 */
char* gen_random_string_alphanumeric(int n) {
  static char cset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  return gen_random_string(n, cset);
}

/*
 * Generate random string with n lower case hex characters.
 */
char* gen_random_string_hex(int n) {
  static char cset[] = "abcdef0123456789";
  return gen_random_string(n, cset);
}

/*
 * show the available ciphers.
 * This is a callback.
 */
static void show_ciphers(const OBJ_NAME *name, void *bio_)
{
  BIO *bio = bio_;
  static int n = 0;

  if (!islower((unsigned char)*name->name)) {
    return;
  }

  if (n == 0) {
    BIO_printf(bio, "   ");
  }
  BIO_printf(bio, "%-25s", name->name);
  if (++n == 3) {
    BIO_printf(bio, "\n");
    n = 0;
  } else {
    BIO_printf(bio, " ");
  }
}

/*
 * show the available message digests.
 * This is a callback.
 */
static void show_mds(const EVP_MD *m, const char *from, const char *to, void *arg)
{
  BIO* bio = arg;
  static int n = 0;

  if (!from) {
    return;
  }
  if (!islower(*from)) {
    return;
  }
  for(const char* p=from; *p; p++) {
    if(isalpha(*p) && !islower(*p)) {
      return;
    }
  }

  if (n == 0) {
    BIO_printf(bio, "   ");
  }
  BIO_printf(bio, "%-25s", from);
  if (++n == 3) {
    BIO_printf(bio, "\n");
    n = 0;
  } else {
    BIO_printf(bio, " ");
  }
}

/*
 * list ciphers and message digests using the callbacks.
 */
void list(struct options_t* opts) {
  BIO* bio_out = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
  BIO_printf(bio_out, "\n");

  BIO_printf(bio_out, "Supported ciphers:\n");
  OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH,
                         show_ciphers, bio_out);
  BIO_printf(bio_out, "\n");

  BIO_printf(bio_out, "\n");
  BIO_printf(bio_out, "Supported message digests:\n");
  EVP_MD_do_all_sorted(show_mds, bio_out);
  BIO_printf(bio_out, "\n");
  BIO_printf(bio_out, "\n");
}

/**
 * pass_prompt
 */
void pass_prompt(struct options_t* opts, const EVP_CIPHER *cipher) {
  if (opts->pass == NULL) {
    char prompt[1024];
    opts->pass = calloc(1, 1024);
    BIO_snprintf(prompt, sizeof(prompt), "enter %s decryption password:",
                 OBJ_nid2ln(EVP_CIPHER_nid(cipher)));
    EVP_read_pw_string(opts->pass, sizeof(prompt), prompt, 0);
  }
}

/*
 * open_input_file
 */
BIO* open_input_file(struct options_t* opts) {
  BIO* rbio;
  if (opts->ifile == NULL) {
    rbio = BIO_new_fp(stdin, BIO_NOCLOSE | BIO_FP_TEXT);
  } else {
    rbio = BIO_new_file(opts->ifile, "rb");
  }
  if (rbio == NULL) {
    ERR("input file open failed!");
  }
  return rbio;
}

/*
 * open_output_file
 */
BIO* open_output_file(struct options_t* opts) {
  BIO* wbio;
  if (opts->ofile == NULL) {
    wbio = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
  } else {
    if (opts->base64) {
      wbio = BIO_new_file(opts->ofile, "wb");
    } else {
      wbio = BIO_new_file(opts->ofile, "wb");
    }
  }
  if (wbio == NULL) {
    ERR("output file open failed!");
  }
  return wbio;
}

/*
 * base64_interposer
 */
void base64_interposer(struct options_t* opts, BIO** bio) {
  if (opts->base64) {
    BIO* b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
      ERR("file open failed!");
    }
    *bio = BIO_push(b64, *bio);
  }
}

/*
 * Encrypt using the openssl BIO idioms.
 */
void encrypt(struct options_t* opts) {
  const EVP_CIPHER *cipher = EVP_get_cipherbyname(opts->cipher);
  const EVP_MD *digest = EVP_get_digestbyname(opts->digest);
  unsigned char key[EVP_MAX_KEY_LENGTH];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  BIO* rbio = NULL;
  BIO* wbio = NULL;
  BIO* benc = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  int bsize = 65536;
  unsigned char *buff = NULL;

  // Verify the cipher and digest.
  if (cipher == NULL) {
    ERR("undefined cipher: %s", opts->cipher);
  }
  if (digest == NULL) {
    ERR("undefined digest: %s", opts->digest);
  }

  pass_prompt(opts, cipher);
  rbio = open_input_file(opts);
  wbio = open_output_file(opts);
  base64_interposer(opts, &wbio);

  // Write the salt - for openssl compatibility.
  BIO_write(wbio, "Salted__", 8);
  BIO_write(wbio, opts->salt, 8);

  // Create the key.
  if (!EVP_BytesToKey(cipher, digest,
                      (const unsigned char*)opts->salt,
                      (const unsigned char *)opts->pass, strlen(opts->pass),
                      opts->rounds, key, iv)) {
    ERR("BytesToKey failed!");
  }

  // Clear the password here for more security!
  OPENSSL_cleanse(opts->pass, strlen(opts->pass));

  // Set the encryption context.
  benc = BIO_new(BIO_f_cipher());
  if (benc == NULL) {
    ERR("benc operation failed!");
  }
  BIO_get_cipher_ctx(benc, &ctx);

  // Initialize the cipher engine.
  if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 1)) {
    ERR("EVP_CipherInit_ex failed!");
  }

  if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 1)) {
    ERR("EVP_CipherInit_ex(ctx failed!");
  }

  /* Only encrypt/decrypt as we write the file */
  wbio = BIO_push(benc, wbio);

  // read input, write encrypted output
  buff = malloc(EVP_ENCODE_LENGTH(bsize));
  if (buff == NULL) {
    ERR("malloc failed!");
  }
  for(;;) {
    int num = BIO_read(rbio, (char *)buff, bsize);
    if (num <= 0) {
      break;
    }

    if (BIO_write(wbio, (char *)buff, num) != num) {
      ERR("write failed!");
    }
  }

  if (!BIO_flush(wbio)) {
    ERR("flush failed!");
  }

  if (opts->verbose) {
    INFO("done");
  }

  // Clean up.
  BIO_free(rbio);
  BIO_free(wbio);
}

/*
 * decrypt
 */
void decrypt(struct options_t* opts) {
  const EVP_CIPHER *cipher = EVP_get_cipherbyname(opts->cipher);
  const EVP_MD *digest = EVP_get_digestbyname(opts->digest);
  unsigned char key[EVP_MAX_KEY_LENGTH];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  BIO* rbio = NULL;
  BIO* wbio = NULL;
  BIO* benc = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  int bsize = 65536;
  unsigned char *buff = NULL;
  unsigned char magic[9]; /* "Salted__" + 1 for NULL */
  unsigned char salt[8];

  // Verify the cipher and digest.
  if (cipher == NULL) {
    ERR("undefined cipher: %s", opts->cipher);
  }
  if (digest == NULL) {
    ERR("undefined digest: %s", opts->digest);
  }

  pass_prompt(opts, cipher);
  rbio = open_input_file(opts);
  wbio = open_output_file(opts);
  base64_interposer(opts, &rbio);

  // Read the salt information
  // and verify the magic header.
  if (BIO_read(rbio, magic, 8) != 8) {
    ERR("error reading input file");
  }
  magic[8] = 0;
  if (memcmp(magic, "Salted__", 8)) {
    ERR("error reading input file - bad salt magic");
  }
  if (BIO_read(rbio, salt, 8) != 8) {
    ERR("error reading input file - salt");
  }
  if (opts->salt == NULL) {
    opts->salt = calloc(1, 9);
    memcpy(opts->salt, salt, 8);
  } else if (memcmp(opts->salt, salt, 8)) {
    WARN("invalid salt specified, decryption will fail");
  }

  // Create the key.
  if (!EVP_BytesToKey(cipher, digest,
                      (const unsigned char*)opts->salt,
                      (const unsigned char *)opts->pass, strlen(opts->pass),
                      opts->rounds, key, iv)) {
    ERR("BytesToKey failed!");
  }

  // Clear the password here for more security!
  OPENSSL_cleanse(opts->pass, strlen(opts->pass));

  // Set the encryption context.
  benc = BIO_new(BIO_f_cipher());
  if (benc == NULL) {
    ERR("benc operation failed!");
  }
  BIO_get_cipher_ctx(benc, &ctx);

  // Initialize the cipher engine.
  if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 0)) {
    ERR("EVP_CipherInit_ex failed!");
  }

  if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 0)) {
    ERR("EVP_CipherInit_ex(ctx failed!");
  }

  /* Only encrypt/decrypt as we write the file */
  wbio = BIO_push(benc, wbio);

  // read input, write encrypted output
  buff = malloc(EVP_ENCODE_LENGTH(bsize));
  if (buff == NULL) {
    ERR("malloc failed!");
  }
  for(;;) {
    int num = BIO_read(rbio, (char *)buff, bsize);
    if (num <= 0) {
      break;
    }

    if (BIO_write(wbio, (char *)buff, num) != num) {
      ERR("write failed!");
    }
  }

  if (!BIO_flush(wbio)) {
    ERR("flush failed!");
  }

  if (opts->verbose) {
    INFO("done");
  }

  // Clean up.
  BIO_free(rbio);
  BIO_free(wbio);
}

/*
 * Get the next command line argument.
 */
char* getnextarg(int argc, char** argv, int *i, const char* opt) {
  if (++(*i) < argc) {
    return newstr(argv[*i]);
  }
  ERR("missing argument for '%s'", opt);
  return NULL;
}

/*
 * Process the command line arguments.
 */
struct options_t* getopts(int argc, char** argv) {
  int i;
  static struct options_t opts;

  srand(time(NULL) + 12345678);

  opts.cipher = NULL;
  opts.digest = NULL;
  opts.rounds = 1;
  opts.salt = NULL;
  opts.pass = NULL;
  opts.ifile = NULL;
  opts.ofile = NULL;
  opts.mode = NOTSET;
  opts.base = basename(argv[0]);
  opts.verbose = 0;
  opts.version = "0.2";

  for(i=1; i<argc; i++) {
    const char* opt = argv[i];
    if (eqn(opt, "-h", "--help", NULL))  {
      help(&opts);
    } else if (eqn(opt, "-a", "--ascii", NULL)) {
      opts.base64 = true;
    } else if (eqn(opt, "-c", "--cipher", NULL)) {
      opts.cipher = getnextarg(argc, argv, &i, opt);
    } else if (eqn(opt, "-d", "--decrypt", NULL)) {
      if (opts.mode != NOTSET) {
        ERR("-d, -e and -l are mutually exclusive");
      }
      opts.mode = DECRYPT;
    } else if (eqn(opt, "-e", "--encrypt", NULL)) {
      if (opts.mode != NOTSET) {
        ERR("-d, -e and -l are mutually exclusive");
      }
      opts.mode = ENCRYPT;
    } else if (eqn(opt, "-i", "--input", NULL)) {
      opts.ifile = getnextarg(argc, argv, &i, opt);
    } else if (eqn(opt, "-l", "--list", NULL)) {
      if (opts.mode != NOTSET) {
        ERR("-d, -e and -l are mutually exclusive");
      }
      opts.mode = LIST;
    } else if (eqn(opt, "-m", "--message-digest", "--digest", NULL)) {
      opts.digest = getnextarg(argc, argv, &i, opt);
    } else if (eqn(opt, "-o", "--output", NULL)) {
      opts.ofile = getnextarg(argc, argv, &i, opt);
    } else if (eqn(opt, "-k", "-p", "--pass", NULL)) {
      opts.pass = getnextarg(argc, argv, &i, opt);
    } else if (eqn(opt, "-r", "--rounds", NULL)) {
      char* n = getnextarg(argc, argv, &i, opt);
      opts.rounds = atoi(n);
      free(n);
    } else if (eqn(opt, "-s", "--salt", NULL)) {
      opts.salt = getnextarg(argc, argv, &i, opt);
    } else if (eqn(opt, "-v", "--verbose", NULL)) {
      opts.verbose++;
    } else if (eqn(opt, "-vv", "-vvv", NULL)) {
      opts.verbose += strlen(opt) - 1;
    } else if (eqn(opt, "-V", "--version", NULL)) {
      printf("%s v%s\n", opts.base, opts.version);
      exit(0);
    } else {
      ERR("unrecognized option '%s'", opt);
    }
  }

  /*
   * Set defaults.
   */
  if (opts.cipher == NULL) {
    opts.cipher = newstr("aes-256-cbc");
  }

  if (opts.digest == NULL) {
    opts.digest = newstr("sha256");
  }

  if (opts.mode == NOTSET) {
    opts.mode = ENCRYPT; /* default */
  }

  /*
   * Salt is tricky.
   * In decryption we use the salt in the encrypted file so
   * it doesn't need to be set explicitly.
   * For encryption a salt must be specified but it can be
   * automatically.
   * If the user specified a salt, honor it (even in decryption).
   */
  if (opts.salt == NULL) {
    if (opts.mode == ENCRYPT) {
      opts.salt = gen_random_string_hex(8);
    }
  } else {
    if (strlen(opts.salt) != 8) {
      ERR("salt has invalid length, must be 8 characters");
    }
  }

  /*
   * Verbose mode info.
   */
  if (opts.verbose > 0) {
    INFO("base64 = %s", (opts.base64 ? "true" : "false"));
    INFO("cipher = %s", opts.cipher);
    INFO("digest = %s", opts.digest);
    INFO("rounds = %d", opts.rounds);
    INFO("input  = '%s'", (opts.ifile == NULL ? "stdin" : opts.ifile));
    INFO("output = '%s'", (opts.ofile == NULL ? "stdout" : opts.ofile));
    if (opts.salt != NULL) {
      INFO("salt   = '%s'", opts.salt);
    }
    INFO("mode   = %s", (opts.mode == ENCRYPT ? "encrypt" :
                         (opts.mode == DECRYPT ? "decrypt" :
                          (opts.mode == LIST ? "list" : "notset"))));
    INFO("version= v%s", opts.version);

    if (opts.mode == ENCRYPT) {
      /* show the openssl decrypt command */
      char buf[1024];
      buf[0] = 0;
      sprintf(buf, "decrypt = openssl %s -d -md %s ", opts.cipher, opts.digest);
      if (opts.base64) {
        strcat(buf, " -a");
      }
      if (opts.pass) {
        strcat(buf, " -k '");
        strcat(buf, opts.pass);
        strcat(buf, "'");
      }
      if (opts.ofile) {
        strcat(buf, " -in '");
        strcat(buf, opts.ofile);
        strcat(buf, "'");
      }
      INFO("%s", buf);
    } else if (opts.mode == DECRYPT) {
      /* show the openssl encrypt command */
      char buf[1024];
      buf[0] = 0;
      sprintf(buf, "encrypt = openssl %s -e -md %s ", opts.cipher, opts.digest);
      if (opts.base64) {
        strcat(buf, " -a");
      }
      if (opts.pass) {
        strcat(buf, " -k '");
        strcat(buf, opts.pass);
        strcat(buf, "'");
      }
      if (opts.ofile) {
        strcat(buf, " -in '");
        strcat(buf, opts.ofile);
        strcat(buf, "'");
      }
      INFO("%s", buf);
    }
  }

  return &opts;
}

/*
 * main
 */
int main(int argc, char** argv) {
  struct options_t* opts = getopts(argc, argv);

  /* Make sure that all algorithms are present. */
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_digests();

  switch (opts->mode) {
  case LIST:
    list(opts);
    break;
  case DECRYPT:
    decrypt(opts);
    break;
  case ENCRYPT:
    encrypt(opts);
    break;
  default:
    {
      ERR("internal error, mode not set properly!");
      break;
    }
  }

  /* All done. */
  EVP_cleanup();

  return 0;
}

/*
 * help shown when the user specifies -h (or --help).
 */
void help(const struct options_t* opts) {
  printf("\n");
  printf("USAGE\n");
  printf("    %s [OPTIONS]\n", opts->base);
  printf("\n");
  printf("DESCRIPTION\n");
  printf("    Encrypts or decrypts a file using the openssl library.\n");
  printf("\n");
  printf("OPTIONS\n");
  printf("    -a, --ascii        Output ASCII, convert to base64.\n");
  printf("\n");
  printf("    -c CIPHER, --cipher CIPHER\n");
  printf("                       The cipher algorithm. The default is aes-256-cbc.\n");
  printf("\n");
  printf("    -d DIGEST, --digest DIGEST\n");
  printf("                       The digest algorithm. The default is sha256.\n");
  printf("\n");
  printf("    -h, --help         This help message.\n");
  printf("\n");
  printf("    -l, --list         List the supported ciphers and digests.\n");
  printf("\n");
  printf("    -i FILE, --input FILE\n");
  printf("                       The input file name. Default is stdin.\n");
  printf("\n");
  printf("    -m DIGEST, --message-digest DIGEST, --digest DIGEST\n");
  printf("                       Specify the message digest to use. The default is sha256.\n");
  printf("                       See the --list output for the available message digests.\n");
  printf("\n");
  printf("    -o FILE, --output FILE\n");
  printf("                       The output file name. Default is stdout.\n");
  printf("\n");
  printf("    -p PASS, --pass PASS, -k PASS\n");
  printf("                       Passphrase. Added -k (key) for openssl compatibility.\n");
  printf("                       If this is not specified, you will be prompted.\n");
  printf("\n");
  printf("    -r ROUNDS, --rounds ROUNDS\n");
  printf("                       Number of rounds. Default is 1.\n");
  printf("\n");
  printf("    -s SALT, --salt SALT\n");
  printf("                       8 character salt used for encryption only.\n");
  printf("                       The decryption algorithm figures out the correct salt but\n");
  printf("                       you can specify it manually. If you do specify it manually\n");
  printf("                       it must match the salt used for encryption.\n");
  printf("\n");
  printf("    -v, --verbose      Increase the level of verbosity.\n");
  printf("\n");
  printf("    -V, --version      Print the program version and exit.\n");
  printf("\n");
  printf("EXAMPLES\n");
  printf("    # Example 1. help\n");
  printf("    $ %s -h\n", opts->base);
  printf("\n");
  printf("    # Example 2. simple encrypt/decrypt example using a pipe\n");
  printf("    $ cat >text <<EOF\n");
  printf("    Lorem ipsum dolor sit amet, graeco propriae volutpat eum ei, eam id\n");
  printf("    fierent conceptam. No per choro tation. Id ipsum zril omnium duo.\n");
  printf("    EOF\n");
  printf("    $ %s -s feedbeef -k password -i text -a -e | \\\n", opts->base);
  printf("      %s -s feedbeef -k password -a -d\n", opts->base);
  printf("    Lorem ipsum dolor sit amet, graeco propriae volutpat eum ei, eam id\n");
  printf("    fierent conceptam. No per choro tation. Id ipsum zril omnium duo.\n");
  printf("\n");
  printf("    # Example 3. encrypt, then decrypt using files\n");
  printf("    $ %s -c aes-256-cbc -m sha512 -s dadafeed -a -e -i text -o text.enc\n", opts->base);
  printf("    $ %s -c aes-256-cbc -m sha512 -s dadafeed -a -d -i text.enc -o text.dec\n", opts->base);
  printf("    $ ls text*\n");
  printf("    text text.dec text.enc\n");
  printf("    $ diff text text.dec\n");
  printf("\n");
  printf("VERSION\n");
  printf("    %s\n", opts->version);
  printf("\n");

  exit(0);
}
