#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <readline/readline.h>
#include <openssl/md5.h>

#define MAX_PASSWORD_LEN 1024
#define DEFAULT_PASSWORD_LEN 8

char DEFAULT_PASSWORD[DEFAULT_PASSWORD_LEN] = "password";
char DEFAULT_PASSWORD_HASHED[MD5_DIGEST_LENGTH];

void test_password(char* user_string, char* password, int len) {
  printf("First: %s\t Second: %s\n", user_string, password);
  if (memcmp(user_string, password, len) == 0) {
    printf("Success!\n");
  } else {
    printf("Error: Incorrect password!\n");
  }
}

void first_test(char* user_string) {
  int len = strnlen(user_string, MAX_PASSWORD_LEN);
  test_password(user_string, DEFAULT_PASSWORD, len);
}

void second_test(char* user_string) {
  char *user_hashed = MD5(user_string, strlen(user_string) , NULL);
  test_password(user_hashed, DEFAULT_PASSWORD_HASHED, strlen(user_hashed));
}

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
