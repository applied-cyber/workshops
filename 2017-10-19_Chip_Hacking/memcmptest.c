#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <readline/readline.h>
#include <openssl/md5.h>

#define MAX_PASSWORD_LEN 1024
#define DEFAULT_PASSWORD_LEN 8

char DEFAULT_PASSWORD[DEFAULT_PASSWORD_LEN] = "password";
char DEFAULT_PASSWORD_HASHED[MD5_DIGEST_LENGTH];

/* Simple function to test password equality */
void test_password(char* user_string, char* password, int len) {
  printf("First: %s\t Second: %s\n", user_string, password);
  // NOTE: Here is the call to memcmp
  if (memcmp(user_string, password, len) == 0) {
    printf("Success!\n");
  } else {
    printf("Error: Incorrect password!\n");
  }
}

/* Simple function which demonstrates the basic version of the
 * problem.
 */
void first_test(char* user_string) {
  int len = strnlen(user_string, MAX_PASSWORD_LEN);
  // Hmm...anything wrong with this function call?
  test_password(user_string, DEFAULT_PASSWORD, len);
}

/* Slightly more advanced version, with the same problem, but now
 * not exploitable. Why?
 */
void second_test(char* user_string) {
  char *user_hashed = MD5(user_string, strlen(user_string) , NULL);
  test_password(user_hashed, DEFAULT_PASSWORD_HASHED, strlen(user_hashed));
}

/* Final "shipped" version of the vulnerability. Hash performed on client
 * side, then sent over an HTTP request. Why is this version vulnerable,
 * but second_test is not?
 */
void third_test(char* hashed_string) {
  char *password_hashed = MD5(DEFAULT_PASSWORD, DEFAULT_PASSWORD_LEN, NULL);
  test_password(hashed_string, password_hashed, strlen(hashed_string));
}

int main() {
  // Init
  MD5(DEFAULT_PASSWORD, DEFAULT_PASSWORD_LEN, DEFAULT_PASSWORD_HASHED);

  char* first_input = readline("Guess at password: ");
  first_test(first_input);
  char* second_input = readline("Guess at password: ");
  second_test(second_input);
  char* third_input = readline("Guess at password: ");
  third_test(third_input);
}
