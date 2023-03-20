package aes

import (
        "encoding/base64"
        "encoding/hex"
        "testing"
)

var origData string = "Hello World" // 待加密的数据
var key = "ABCDEFGHIJKLMNOP"        // 加密的密钥

func Test_AesEncryptCBC(t *testing.T) {
        a, err := NewAes(key, MODE_CBC)
        if err != nil {
                t.Logf("new aes cbc mode faild, msg:%s", err.Error())
                return
        }
        d, err := a.Encrypt(origData)
        if err != nil {
                t.Logf("aes cbc mode encrypt faild, msg:%s", err.Error())
                return
        }

        t.Log("密文(hex)：", hex.EncodeToString(d))
        t.Log("密文(base64)：", base64.StdEncoding.EncodeToString(d))

        decrypted, err := a.Decrypt(string(d))
        if err != nil {
                t.Logf("aes cbc mode decrypt faild, msg:%s", err.Error())
                return
        }
        t.Log("解密结果：", string(decrypted))
}

func Test_AesEncryptECB(t *testing.T) {
        a, err := NewAes(key, MODE_ECB)
        if err != nil {
                t.Logf("new aes ecb mode faild, msg:%s", err.Error())
                return
        }
        d, err := a.Encrypt(origData)
        if err != nil {
                t.Logf("aes ecb mode encrypt faild, msg:%s", err.Error())
                return
        }

        t.Log("ecb 密文(hex)：", hex.EncodeToString(d))
        t.Log("ecb 密文(base64)：", base64.StdEncoding.EncodeToString(d))

        decrypted, err := a.Decrypt(string(d))
        if err != nil {
                t.Logf("aes ecb mode decrypt faild, msg:%s", err.Error())
                return
        }
        t.Log("ecb 解密结果：", string(decrypted))
}

func Test_AesEncryptCFB(t *testing.T) {
        a, err := NewAes(key, MODE_CFB)
        if err != nil {
                t.Logf("new aes cfb mode faild, msg:%s", err.Error())
                return
        }
        d, err := a.Encrypt(origData)
        if err != nil {
                t.Logf("aes cfb mode encrypt faild, msg:%s", err.Error())
                return
        }

        t.Log("cfb 密文(hex)：", hex.EncodeToString(d))
        t.Log("cfb 密文(base64)：", base64.StdEncoding.EncodeToString(d))

        decrypted, err := a.Decrypt(string(d))
        if err != nil {
                t.Logf("aes cfb mode decrypt faild, msg:%s", err.Error())
                return
        }
        t.Log("cfb 解密结果：", string(decrypted))
}