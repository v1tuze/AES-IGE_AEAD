/**
 * AES-IGE-AEAD Python C Extension
 * CPython 3.7+ binding for the C library
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "aes_ige_aead.h"
#include "chacha20_poly1305.h"

static PyObject *AesIgeAeadError;

static PyObject *encrypt(PyObject *self, PyObject *args, PyObject *kwargs) {
    Py_buffer key_buf, iv_buf, plaintext_buf, aad_buf;
    const uint8_t *aad_ptr = NULL;
    Py_ssize_t aad_len = 0;
    Py_ssize_t ct_size, ct_len;
    PyObject *result = NULL;
    static char *kwlist[] = {"key", "iv", "plaintext", "aad", NULL};

    key_buf.buf = iv_buf.buf = plaintext_buf.buf = aad_buf.buf = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y*y*y*|y*", kwlist,
            &key_buf, &iv_buf, &plaintext_buf, &aad_buf))
        return NULL;
    if (aad_buf.buf) { aad_ptr = (const uint8_t *)aad_buf.buf; aad_len = aad_buf.len; }

    if (key_buf.len != AES_IGE_AEAD_KEY_SIZE) {
        PyErr_Format(PyExc_ValueError, "key must be %d bytes, got %zd",
                     AES_IGE_AEAD_KEY_SIZE, key_buf.len);
        goto cleanup;
    }
    if (iv_buf.len != AES_IGE_AEAD_IV_SIZE) {
        PyErr_Format(PyExc_ValueError, "iv must be %d bytes, got %zd",
                     AES_IGE_AEAD_IV_SIZE, iv_buf.len);
        goto cleanup;
    }

    ct_size = (Py_ssize_t)aes_ige_aead_encrypt_size((size_t)plaintext_buf.len);
    result = PyBytes_FromStringAndSize(NULL, ct_size);
    if (!result) goto cleanup;

    ct_len = aes_ige_aead_encrypt(
        (const uint8_t *)key_buf.buf,
        (const uint8_t *)iv_buf.buf,
        aad_ptr,
        (size_t)aad_len,
        (const uint8_t *)plaintext_buf.buf,
        (size_t)plaintext_buf.len,
        (uint8_t *)PyBytes_AS_STRING(result));

    if (ct_len < 0) {
        Py_CLEAR(result);
        PyErr_SetString(AesIgeAeadError, "Encryption failed");
        goto cleanup;
    }
    if (ct_len != ct_size) {
        if (_PyBytes_Resize(&result, ct_len) < 0) {
            Py_CLEAR(result);
            goto cleanup;
        }
    }

cleanup:
    if (aad_buf.buf) PyBuffer_Release(&aad_buf);
    PyBuffer_Release(&plaintext_buf);
    PyBuffer_Release(&iv_buf);
    PyBuffer_Release(&key_buf);
    return result;
}

static PyObject *decrypt(PyObject *self, PyObject *args, PyObject *kwargs) {
    Py_buffer key_buf, ciphertext_buf, aad_buf;
    const uint8_t *aad_ptr = NULL;
    Py_ssize_t aad_len = 0;
    Py_ssize_t pt_size, pt_len;
    PyObject *result = NULL;
    static char *kwlist[] = {"key", "ciphertext", "aad", NULL};

    key_buf.buf = ciphertext_buf.buf = aad_buf.buf = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y*y*|y*", kwlist,
            &key_buf, &ciphertext_buf, &aad_buf))
        return NULL;
    if (aad_buf.buf) { aad_ptr = (const uint8_t *)aad_buf.buf; aad_len = aad_buf.len; }

    if (key_buf.len != AES_IGE_AEAD_KEY_SIZE) {
        PyErr_Format(PyExc_ValueError, "key must be %d bytes, got %zd",
                     AES_IGE_AEAD_KEY_SIZE, key_buf.len);
        goto cleanup;
    }

    pt_size = (Py_ssize_t)aes_ige_aead_decrypt_size((size_t)ciphertext_buf.len);
    if (pt_size <= 0) {
        PyErr_SetString(AesIgeAeadError, "Invalid ciphertext or authentication failed");
        goto cleanup;
    }

    result = PyBytes_FromStringAndSize(NULL, pt_size);
    if (!result) goto cleanup;

    pt_len = aes_ige_aead_decrypt(
        (const uint8_t *)key_buf.buf,
        aad_ptr,
        (size_t)aad_len,
        (const uint8_t *)ciphertext_buf.buf,
        (size_t)ciphertext_buf.len,
        (uint8_t *)PyBytes_AS_STRING(result));

    if (pt_len < 0) {
        Py_CLEAR(result);
        PyErr_SetString(AesIgeAeadError, "Decryption failed or authentication failed");
        goto cleanup;
    }
    if (_PyBytes_Resize(&result, pt_len) < 0) {
        Py_CLEAR(result);
        goto cleanup;
    }

cleanup:
    if (aad_buf.buf) PyBuffer_Release(&aad_buf);
    PyBuffer_Release(&ciphertext_buf);
    PyBuffer_Release(&key_buf);
    return result;
}

static PyObject *encrypt_size(PyObject *self, PyObject *arg) {
    Py_ssize_t n = PyLong_AsSsize_t(arg);
    if (n == -1 && PyErr_Occurred()) return NULL;
    if (n < 0) {
        PyErr_SetString(PyExc_ValueError, "plaintext length must be non-negative");
        return NULL;
    }
    return PyLong_FromSsize_t((Py_ssize_t)aes_ige_aead_encrypt_size((size_t)n));
}

static PyObject *decrypt_size(PyObject *self, PyObject *arg) {
    Py_ssize_t n = PyLong_AsSsize_t(arg);
    if (n == -1 && PyErr_Occurred()) return NULL;
    if (n < 0) {
        PyErr_SetString(PyExc_ValueError, "ciphertext length must be non-negative");
        return NULL;
    }
    return PyLong_FromSsize_t((Py_ssize_t)aes_ige_aead_decrypt_size((size_t)n));
}

static PyObject *chacha20_poly1305_encrypt_fn(PyObject *self, PyObject *args, PyObject *kwargs) {
    Py_buffer key_buf, nonce_buf, plaintext_buf, aad_buf;
    const uint8_t *aad_ptr = NULL;
    Py_ssize_t aad_len = 0;
    Py_ssize_t ct_size, ct_len;
    PyObject *result = NULL;
    static char *kwlist[] = {"key", "nonce", "plaintext", "aad", NULL};

    key_buf.buf = nonce_buf.buf = plaintext_buf.buf = aad_buf.buf = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y*y*y*|y*", kwlist,
            &key_buf, &nonce_buf, &plaintext_buf, &aad_buf))
        return NULL;
    if (aad_buf.buf) { aad_ptr = (const uint8_t *)aad_buf.buf; aad_len = aad_buf.len; }
    if (key_buf.len != 32) { PyErr_SetString(PyExc_ValueError, "key must be 32 bytes"); goto out; }
    if (nonce_buf.len != 12) { PyErr_SetString(PyExc_ValueError, "nonce must be 12 bytes"); goto out; }
    ct_size = (Py_ssize_t)chacha20_poly1305_encrypt_size((size_t)plaintext_buf.len);
    result = PyBytes_FromStringAndSize(NULL, ct_size);
    if (!result) goto out;
    ct_len = chacha20_poly1305_encrypt((const uint8_t *)key_buf.buf,
        (const uint8_t *)nonce_buf.buf, aad_ptr, (size_t)aad_len,
        (const uint8_t *)plaintext_buf.buf, (size_t)plaintext_buf.len,
        (uint8_t *)PyBytes_AS_STRING(result));
    if (ct_len < 0) { Py_CLEAR(result); PyErr_SetString(AesIgeAeadError, "Encrypt failed"); goto out; }
    if (ct_len != ct_size && _PyBytes_Resize(&result, ct_len) < 0) { Py_CLEAR(result); goto out; }
out:
    if (aad_buf.buf) PyBuffer_Release(&aad_buf);
    PyBuffer_Release(&plaintext_buf);
    PyBuffer_Release(&nonce_buf);
    PyBuffer_Release(&key_buf);
    return result;
}

static PyObject *chacha20_poly1305_decrypt_fn(PyObject *self, PyObject *args, PyObject *kwargs) {
    Py_buffer key_buf, ciphertext_buf, aad_buf;
    const uint8_t *aad_ptr = NULL;
    Py_ssize_t aad_len = 0;
    Py_ssize_t pt_size, pt_len;
    PyObject *result = NULL;
    static char *kwlist[] = {"key", "ciphertext", "aad", NULL};

    key_buf.buf = ciphertext_buf.buf = aad_buf.buf = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y*y*|y*", kwlist,
            &key_buf, &ciphertext_buf, &aad_buf))
        return NULL;
    if (aad_buf.buf) { aad_ptr = (const uint8_t *)aad_buf.buf; aad_len = aad_buf.len; }
    if (key_buf.len != 32) { PyErr_SetString(PyExc_ValueError, "key must be 32 bytes"); goto out; }
    pt_size = (Py_ssize_t)chacha20_poly1305_decrypt_size((size_t)ciphertext_buf.len);
    if (pt_size <= 0) { PyErr_SetString(AesIgeAeadError, "Invalid ciphertext or auth failed"); goto out; }
    result = PyBytes_FromStringAndSize(NULL, pt_size);
    if (!result) goto out;
    pt_len = chacha20_poly1305_decrypt((const uint8_t *)key_buf.buf, aad_ptr, (size_t)aad_len,
        (const uint8_t *)ciphertext_buf.buf, (size_t)ciphertext_buf.len,
        (uint8_t *)PyBytes_AS_STRING(result));
    if (pt_len < 0) { Py_CLEAR(result); PyErr_SetString(AesIgeAeadError, "Decrypt failed"); goto out; }
    if (_PyBytes_Resize(&result, pt_len) < 0) { Py_CLEAR(result); goto out; }
out:
    if (aad_buf.buf) PyBuffer_Release(&aad_buf);
    PyBuffer_Release(&ciphertext_buf);
    PyBuffer_Release(&key_buf);
    return result;
}

static PyMethodDef module_methods[] = {
    {"encrypt", (PyCFunction)encrypt, METH_VARARGS | METH_KEYWORDS,
     "encrypt(key, iv, plaintext, aad=None) -> bytes"},
    {"decrypt", (PyCFunction)decrypt, METH_VARARGS | METH_KEYWORDS,
     "decrypt(key, ciphertext, aad=None) -> bytes"},
    {"chacha20_poly1305_encrypt", (PyCFunction)chacha20_poly1305_encrypt_fn, METH_VARARGS | METH_KEYWORDS,
     "chacha20_poly1305_encrypt(key, nonce, plaintext, aad=None) -> bytes"},
    {"chacha20_poly1305_decrypt", (PyCFunction)chacha20_poly1305_decrypt_fn, METH_VARARGS | METH_KEYWORDS,
     "chacha20_poly1305_decrypt(key, ciphertext, aad=None) -> bytes"},
    {"encrypt_size", encrypt_size, METH_O, "encrypt_size(plaintext_len) -> int"},
    {"decrypt_size", decrypt_size, METH_O, "decrypt_size(ciphertext_len) -> int"},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef aes_ige_aead_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "aes_ige_aead",
    .m_doc = "AES-IGE-AEAD: Authenticated encryption (CPython C extension)",
    .m_size = -1,
    .m_methods = module_methods,
};

PyMODINIT_FUNC PyInit_aes_ige_aead(void) {
    PyObject *m = PyModule_Create(&aes_ige_aead_module);
    if (m == NULL) return NULL;

    AesIgeAeadError = PyErr_NewException("aes_ige_aead.AesIgeAeadError", PyExc_ValueError, NULL);
    if (AesIgeAeadError) {
        Py_INCREF(AesIgeAeadError);
        PyModule_AddObject(m, "AesIgeAeadError", AesIgeAeadError);
    }

    PyModule_AddIntConstant(m, "KEY_SIZE", AES_IGE_AEAD_KEY_SIZE);
    PyModule_AddIntConstant(m, "IV_SIZE", AES_IGE_AEAD_IV_SIZE);
    PyModule_AddIntConstant(m, "TAG_SIZE", AES_IGE_AEAD_TAG_SIZE);
    PyModule_AddIntConstant(m, "CHACHA20_POLY1305_NONCE_SIZE", CHACHA20_POLY1305_NONCE_SIZE);

    return m;
}
