#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha3.h"

int process(char* buf, unsigned long long len, unsigned long long offset)
{
    char d;
    for (; offset < len - 1; offset++)
    {
        d = buf[offset] - buf[len - offset - 1];
        buf[offset] = 256 * (d < 0) + d;
    }
    return 0;
}

int deprocess(char* buf, unsigned long long len)
{
    for (long long offset = len - 2; offset > -1; offset--)
    {
        buf[offset] = (buf[offset] + buf[len - offset - 1]) & 0xff;
    }
    return 0;
}

int encrypt(char* buf, unsigned long long len, char* pw)
{
    unsigned long long pwlen = strlen(pw);
    unsigned long long hashlen = max(pwlen + !!(pwlen % 64) * (64 - pwlen % 64), len + !!(len % 64) * (64 - len % 64));
    unsigned long long buflen = len + hashlen;
    int extra = (len + pwlen) % 2;
    buflen += extra;
    char* tbuf = malloc(buflen);
    if (!tbuf)
    {
        return 0;
    }
    memset(tbuf, 0, buflen);
    memcpy(tbuf, buf, len);
    unsigned long long cursize = 0, offset = 0;
    while (pwlen - offset)
    {
        sha3_HashBuffer(512, 0, pw + offset, min(pwlen - offset, 64), tbuf + len + offset, hashlen - offset);
        offset += min(pwlen - offset, 64);
        cursize += 64;
    }
    while (hashlen - cursize)
    {
        sha3_HashBuffer(512, 0, tbuf + len, cursize, tbuf + len + cursize, hashlen - cursize);
        cursize += 64;
    }
    if (extra)
    {
        tbuf[len + cursize] = tbuf[len + cursize - 1];
    }
    process(tbuf + len, cursize + extra, 0);
    process(tbuf, buflen, 0);
    memcpy(buf, tbuf, len);
    free(tbuf);
    return 1;
}

int decrypt(char* buf, unsigned long long len, char* pw)
{
    unsigned long long pwlen = strlen(pw);
    unsigned long long hashlen = max(pwlen + !!(pwlen % 64) * (64 - pwlen % 64), len + !!(len % 64) * (64 - len % 64));
    unsigned long long buflen = len + hashlen;
    int extra = (len + pwlen) % 2;
    buflen += extra;
    char* tbuf = malloc(buflen);
    if (!tbuf)
    {
        return 0;
    }
    memset(tbuf, 0, buflen);
    memcpy(tbuf, buf, len);
    unsigned long long cursize = 0, offset = 0;
    while (pwlen - offset)
    {
        sha3_HashBuffer(512, 0, pw + offset, min(pwlen - offset, 64), tbuf + len + offset, hashlen - offset);
        offset += min(pwlen - offset, 64);
        cursize += 64;
    }
    while (hashlen - cursize)
    {
        sha3_HashBuffer(512, 0, tbuf + len, cursize, tbuf + len + cursize, hashlen - cursize);
        cursize += 64;
    }
    if (extra)
    {
        tbuf[len + cursize] = tbuf[len + cursize - 1];
    }
    process(tbuf + len, cursize + extra, 0);
    process(tbuf, buflen, len);
    deprocess(tbuf, buflen);
    memcpy(buf, tbuf, len);
    free(tbuf);
    return 1;
}

int main()
{
    char* pw = "Hello, World!";
    unsigned long long len = 5;
    char* data = malloc(len + 1);
    data = "Tests";
    printf(data);
    printf("\n");

    process(data, len + len % 2, 0);
    for (unsigned long long i = 0; i < len; i++)
    {
        printf("%u ", data[i] & 0xff);
    }
    printf("\n");

    deprocess(data, len + len % 2);
    printf(data);
    printf("\n");
    
    printf("%u", encrypt(data, len, pw));
    printf("\n");
    for (unsigned long long i = 0; i < len; i++)
    {
        printf("%u ", data[i] & 0xff);
    }
    printf("\n");

    decrypt(data, len, pw);
    printf(data);
    printf("\n");

    free(data);
    return 0;
}
