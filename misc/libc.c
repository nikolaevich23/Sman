#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <math.h>
#include <errno.h>
#include <time.h>

// external
extern int stdc_E1E83C65(const char *str1, const char *str2, size_t num);             // strncmp()
inline int strncmp(const char *str1, const char *str2, size_t num) {return stdc_E1E83C65(str1, str2, num);}
#define strncmp_ stdc_E1E83C65

extern int stdc_3D85D6F8(const char *str1, const char *str2);                         // strcmp()
inline int strcmp(const char *str1, const char *str2) {return stdc_3D85D6F8(str1, str2);}
#define strcmp_ stdc_3D85D6F8

extern size_t stdc_2F45D39C(const char *str);                                         // strlen()
inline size_t strlen(const char *str) {return stdc_2F45D39C(str);}
#define strlen_ stdc_2F45D39C

extern void *stdc_5909E3C4(void *str, int c, size_t n);                               // memset()
inline void* memset(void *str, int c, size_t n) {return stdc_5909E3C4(str, c, n);}
#define memset_ stdc_5909E3C4

extern void *stdc_831D70A5(void *dest, const void *src, size_t num);					// memcpy()
inline void* memcpy(void *dest, const void *src, size_t num) {return stdc_831D70A5(dest, src, num);}
#define memcpy_ stdc_831D70A5

extern char *stdc_C5C09834(const char *str1, const char *str2);							// strstr()
inline char* strstr(const char *str1, const char *str2) {return stdc_C5C09834(str1, str2);}
#define strstr_ stdc_C5C09834

inline int* _Geterrno(void){return stdc_44115DD0();}			// _Geterrno

extern void allocator_77A602DD(void *ptr);						// free()
inline void free(void *ptr) {allocator_77A602DD(ptr);}
#define free_ allocator_77A602DD

extern void *allocator_759E0635(size_t size);					// malloc()
inline void* malloc (size_t size) {return allocator_759E0635(size);}
#define malloc_ allocator_759E0635

extern void *allocator_6137D196(size_t alignment, size_t size);	// memalign()
inline void* memalign(size_t alignment, size_t size) {return allocator_6137D196(alignment, size);}

extern void *allocator_A72A7595(size_t nitems, size_t size);	// calloc()
inline void* calloc(size_t nitems, size_t size) {return allocator_A72A7595(nitems, size);}

extern void *allocator_F7A14A22(void *ptr, size_t size);		// realloc()
inline void* realloc(void *ptr, size_t size) {return allocator_F7A14A22(ptr, size);}

extern void *stdc_5B162B7F(void *str1, const void *str2, size_t n); // memmove()
inline void* memmove(void *str1, const void *str2, size_t n) {return stdc_5B162B7F(str1, str2, n);}

extern char *stdc_FC0428A6(const char *s);						// strdup()
inline char* strdup(const char *s) {return stdc_FC0428A6(s);}

extern char *stdc_44796E5C(int errnum);                         // strerror()
inline char* strerror(int errnum) {return stdc_44796E5C(errnum);}

extern double stdc_519EBB77(double x);                          // floor()
inline double floor(double x) {return stdc_519EBB77(x);}

extern double stdc_21E6D304(double x);                          // ceil()
inline double ceil(double x) {return stdc_21E6D304(x);}

extern time_t stdc_89F6F026(time_t *timer);                     // time()
inline time_t time(time_t *timer) {return stdc_89F6F026(timer);}

extern size_t stdc_FCAC2E8E(wchar_t *dest, const char *src, size_t max);              // mbstowcs()
inline size_t mbstowcs(wchar_t *dest, const char *src, size_t max) {return stdc_FCAC2E8E(dest, src, max);}

extern size_t stdc_12A55FB7(wchar_t *restrict pwc, const char *restrict s, size_t n, mbstate_t *restrict ps); // mbrtowc
int mbtowc(wchar_t * restrict pwc, const char * restrict s, size_t n)
{
   static mbstate_t mbs;
   size_t rval;

   if (s == NULL) {
     stdc_5909E3C4(&mbs, 0, sizeof(mbs)); //memset
     return (0);
   }
   rval = stdc_12A55FB7(pwc, s, n, &mbs); //mbrtowc
   if (rval == (size_t)-1 || rval == (size_t)-2)
     return (-1);
   return ((int)rval);
}

extern size_t stdc_B2702E15(char *pmb, wchar_t wc, mbstate_t *ps); // wcrtomb()
int wctomb(char *s, wchar_t wchar)
{
   static mbstate_t mbs;
   size_t rval;

   if (s == NULL) {
     stdc_5909E3C4(&mbs, 0, sizeof(mbs)); //memset
     return (0);
   }
   if ((rval = stdc_B2702E15(s, wchar, &mbs)) == (size_t)-1) //wcrtomb
     return (-1);
   return ((int)rval);
}

extern int stdc_C3E14CBE(const void *ptr1, const void *ptr2, size_t num);             // memcmp()
inline int memcmp(const void *ptr1, const void *ptr2, size_t num) {return stdc_C3E14CBE(ptr1, ptr2, num);}

extern char *stdc_DEBEE2AF(const char *str, int c);                                         // strchr()
inline char* strchr(const char *str, int c) {return stdc_DEBEE2AF(str, c);}
#define strchr_ stdc_DEBEE2AF

extern char *stdc_73EAE03D(const char *s, int c);                                     // strrchr()
inline char* strrchr(const char *s, int c) {return stdc_73EAE03D(s, c);}
#define strrchr_ stdc_73EAE03D

extern char *stdc_04A183FC(char *dest, const char *src);                              // strcpy()
inline char* strcpy(char *dest, const char *src) {return stdc_04A183FC(dest, src);}
#define strcpy_ stdc_04A183FC

extern char *stdc_8AB0ABC6(char *dest, const char *src, size_t num);                  // strncpy()
inline char* strncpy(char *dest, const char *src, size_t num) {return stdc_8AB0ABC6(dest, src, num);}
#define strncpy_ stdc_8AB0ABC6

extern char *stdc_AA9635D7(char *dest, const char *src);                              // strcat()
inline char* strcat(char *dest, const char *src) {return stdc_AA9635D7(dest, src);}
#define strcat_ stdc_AA9635D7

extern int stdc_B6257E3D(const char *s1, const char *s2, size_t n);                   // strncasecmp()
inline int strncasecmp(const char *s1, const char *s2, size_t n) {return stdc_B6257E3D(s1, s2, n);}

extern int stdc_B6D92AC3(const char *s1, const char *s2);                             // strcasecmp()
inline int strcasecmp(const char *s1, const char *s2) {return stdc_B6D92AC3(s1, s2);}

extern char *stdc_E40BA755(char *str, const char *delimiters);                        // strtok()
inline char* strtok(char *str, const char *delimiters) {return stdc_E40BA755(str, delimiters);}

extern struct tm *stdc_266311A0(const time_t *timer);                                 // localtime()
inline struct tm* localtime(const time_t *timer) {return stdc_266311A0(timer);}

//internal

size_t strcspn(const char *s1, const char *s2)
{
    size_t ret=0;
    while(*s1)
        if(strchr(s2,*s1))
            return ret;
        else
            s1++,ret++;
    return ret;
}

int my_atoi(const char *c);
int my_atoi(const char *c)
{
    int previous_result=0, result=0;
    int multiplier=1;

    if (c && *c == '-')
    {
        multiplier = -1;
        c++;
    }
    else
    {
        multiplier = 1;
    }

    while (*c)
    {
        if (*c < '0' || *c > '9')
        {
            return result * multiplier;
        }
        result *= 10;
        if (result < previous_result)
        {

            return(0);
        }
        else
        {
            previous_result *= 10;
        }

        result += *c - '0';

        if (result < previous_result)
        {

            return(0);
        }
        else
        {
            previous_result += *c - '0';
        }
        c++;
    }
    return(result * multiplier);
}

/*
size_t strspn(const char *s1, const char *s2)
{
    size_t ret=0;
    while(*s1 && strchr(s2,*s1++))
        ret++;
    return ret;
}


int strncasecmp (__const char *s1, __const char *s2, size_t n)
{
  int c1, c2;
  while (n > 0)
    {
      c1 = *((unsigned char *)(s1++));
      if (c1 >= 'A' && c1 <= 'Z')
        c1 = c1 + ('a' - 'A');
      c2 = *((unsigned char *)(s2++));
      if (c2 >= 'A' && c2 <= 'Z')
        c2 = c2 + ('a' - 'A');
      if (c1 != c2)
        {
          return (c1 - c2);
        }
      if (c1 == '\0')
        {
          return 0;
        }
      --n;
    }
  return 0;
}

int strcasecmp (__const char *s1, __const char *s2)
{
  int c1, c2, n;
  n=strlen(s1);
  while (n > 0)
    {
      c1 = *((unsigned char *)(s1++));
      if (c1 >= 'A' && c1 <= 'Z')
        c1 = c1 + ('a' - 'A');
      c2 = *((unsigned char *)(s2++));
      if (c2 >= 'A' && c2 <= 'Z')
        c2 = c2 + ('a' - 'A');
      if (c1 != c2)
        {
          return (c1 - c2);
        }
      if (c1 == '\0')
        {
          return 0;
        }
      --n;
    }
  return 0;
}

char *strtok(char * str, const char * delim)
{
    static char* p=0;
    if(str)
        p=str;
    else if(!p)
        return 0;
    str=p+strspn(p,delim);
    p=str+strcspn(str,delim);
    if(p==str)
        return p=0;
    p = *p ? *p=0,p+1 : 0;
    return str;
}

void *memset(void *m, int c, size_t n)
{
	char *s = (char *) m;

	while (n-- != 0)
	{
		*s++ = (char) c;
	}

	return m;
}

void *memcpy(void *dst0, const void *src0, size_t len0)
{
	char *dst = (char *)dst0;
	char *src = (char *)src0;

	void *save = dst0;

	while (len0--)
		*dst++ = *src++;

	return save;
}


int memcmp(const void* s1, const void* s2,size_t n)
{
    const unsigned char *p1 = s1, *p2 = s2;
    while(n--)
        if( *p1 != *p2 )
            return *p1 - *p2;
        else
            *p1++,*p2++;
    return 0;
}


size_t strlen(const char *s) {
    const char *p = s;
    while (*s) ++s;
    return s - p;
}


char *strchr(const char *s, int c)
{
    while (*s != (char)c)
        if (!*s++)
            return 0;
    return (char *)s;
}

char *strrchr(const char *s, int c)
{
    char* ret=0;
    do {
        if( *s == (char)c )
            ret=s;
    } while(*s++);
    return ret;
}

char *strstr(const char *s1, const char *s2)
{
    size_t n = strlen(s2);
    while(*s1)
        if(!memcmp(s1++,s2,n))
            return s1-1;
    return 0;
}
*/

/*int strncmp(const char* s1, const char* s2, size_t n)
{
	if(n==0) return 0;
    while(*s1 && (*s1==*s2))
	{
        s1++,s2++;
		n--;
		if(n==0) break;
	}
    return *(const unsigned char*)s1-*(const unsigned char*)s2;
}

int strcmp(const char* s1, const char* s2)
{
    while(*s1 && (*s1==*s2))
        s1++,s2++;
    return *(const unsigned char*)s1-*(const unsigned char*)s2;
}


char *strcpy(char *dest, const char* src)
{
    char *ret = dest;
    while (*dest++ = *src++)
        ;
    return ret;
}


char *strncpy(char *dest, const char *src, size_t n)
{
    char *ret = dest;
    do {
        if (!n--)
            return ret;
    } while (*dest++ = *src++);
    while (n--)
        *dest++ = 0;
    return ret;
}

char *strcat(char *dest, const char *src)
{
    char *ret = dest;
    while (*dest)
        dest++;
    while (*dest++ = *src++)
        ;
    return ret;
}
*/