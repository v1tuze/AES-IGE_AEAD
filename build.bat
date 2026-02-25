@echo off
setlocal
set INC=include
set SRC=src
set OUT=.
echo Building AES-IGE-AEAD Library...
gcc -Wall -std=c99 -I%INC% -O2 -c %SRC%/sha256.c -o %SRC%/sha256.o
gcc -Wall -std=c99 -I%INC% -O2 -c %SRC%/aes.c -o %SRC%/aes.o
gcc -Wall -std=c99 -I%INC% -O2 -c %SRC%/gf128.c -o %SRC%/gf128.o
gcc -Wall -std=c99 -I%INC% -O2 -c %SRC%/aes_ige.c -o %SRC%/aes_ige.o
gcc -Wall -std=c99 -I%INC% -O2 -c %SRC%/poly_mac.c -o %SRC%/poly_mac.o
gcc -Wall -std=c99 -I%INC% -O2 -c %SRC%/aes_ige_aead.c -o %SRC%/aes_ige_aead.o
gcc -Wall -std=c99 -I%INC% -O2 -c %SRC%/chacha20.c -o %SRC%/chacha20.o
gcc -Wall -std=c99 -I%INC% -O2 -c %SRC%/poly1305.c -o %SRC%/poly1305.o
gcc -Wall -std=c99 -I%INC% -O2 -c %SRC%/chacha20_poly1305.c -o %SRC%/chacha20_poly1305.o
gcc -Wall -std=c99 -I%INC% -O2 -c %SRC%/deoxys_bc.c -o %SRC%/deoxys_bc.o
gcc -Wall -std=c99 -I%INC% -O2 -c %SRC%/deoxys.c -o %SRC%/deoxys.o
if %errorlevel% neq 0 exit /b 1

echo Creating static library...
ar rcs libaes_ige_aead.a %SRC%/sha256.o %SRC%/aes.o %SRC%/gf128.o %SRC%/aes_ige.o %SRC%/poly_mac.o %SRC%/aes_ige_aead.o %SRC%/chacha20.o %SRC%/poly1305.o %SRC%/chacha20_poly1305.o %SRC%/deoxys_bc.o %SRC%/deoxys.o
ranlib libaes_ige_aead.a 2>nul

echo Building test_vectors...
gcc -o test_vectors.exe %SRC%/sha256.o %SRC%/aes.o %SRC%/gf128.o %SRC%/aes_ige.o %SRC%/poly_mac.o %SRC%/aes_ige_aead.o %SRC%/chacha20.o %SRC%/poly1305.o %SRC%/chacha20_poly1305.o %SRC%/deoxys_bc.o %SRC%/deoxys.o tests/test_vectors.c -I%INC%
if %errorlevel% neq 0 exit /b 1

echo Building demo...
gcc -o demo.exe %SRC%/sha256.o %SRC%/aes.o %SRC%/gf128.o %SRC%/aes_ige.o %SRC%/poly_mac.o %SRC%/aes_ige_aead.o %SRC%/chacha20.o %SRC%/poly1305.o %SRC%/chacha20_poly1305.o %SRC%/deoxys_bc.o %SRC%/deoxys.o demo/demo.c -I%INC%
if %errorlevel% neq 0 exit /b 1

echo.
echo Running tests...
test_vectors.exe
set TERR=%errorlevel%
echo.
if %TERR% equ 0 (
  echo Running demo...
  demo.exe
)
exit /b %TERR%
