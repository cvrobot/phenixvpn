/**
  crypto.h

  Copyright (C) 2015 clowwindy

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef CRYPTO_H
#define CRYPTO_H

/* call once after start */
int crypto_init();

// TODO use a struct to hold context instead
/* call when password changed */
int crypto_set_password(const char *password, unsigned long long password_len);
unsigned char *crypto_gen_key(const char *password, unsigned long long password_len);
int crypto_set_token(unsigned char *c, unsigned int token);
int crypto_get_token(unsigned char *c, unsigned int *token);
int crypto_encrypt_ext(unsigned char *c, unsigned char *m, unsigned long long mlen, unsigned char *k);
int crypto_encrypt(unsigned char *c, unsigned char *m, unsigned long long mlen);
int crypto_decrypt_ext(unsigned char *m, unsigned char *c, unsigned long long clen, unsigned char *k);
int crypto_decrypt(unsigned char *m, unsigned char *c, unsigned long long clen);

#define SHADOWVPN_KEY_LEN 32
#define SHADOWVPN_ZERO_BYTES 32
#define SHADOWVPN_OVERHEAD_LEN 32
#
//tun_buf:salsa208_REV,nonce,mac,data
//udp_buf:token cipher(,8),nonce(8),mac(16),ciphertext
//overhead: nonce + mac
#endif
