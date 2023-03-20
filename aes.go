package aes

import (
        "bytes"
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "fmt"
        "io"
)

type MODE int

const (
        MODE_CBC MODE = 1
        MODE_ECB MODE = 2
        MODE_CFB MODE = 3
)

type Aes struct {
        key   []byte
        mode  MODE
        block cipher.Block
        bs    int
}

func NewAes(k string, mode MODE) (a *Aes, err error) {
        block, err := aes.NewCipher([]byte(k))
        if err != nil {
                return
        }

        bs := block.BlockSize()
        if bs != 16 && bs != 24 && bs != 32 {
                err = fmt.Errorf("key size is not 16 or 24 or 32, current key size is %d", bs)
                return
        }

        a = &Aes{
                key:   []byte(k),
                mode:  mode,
                block: block,
                bs:    bs,
        }
        return
}

func (a *Aes) Encrypt(data string) (d []byte, err error) {
        switch a.mode {
        case MODE_CBC:
                d = a.AesEncryptCBC([]byte(data))
        case MODE_ECB:
                d = a.AesEncryptECB([]byte(data))
        case MODE_CFB:
                d = a.AesEncryptCFB([]byte(data))
        }
        return
}

func (a *Aes) Decrypt(data string) (d []byte, err error) {
        switch a.mode {
        case MODE_CBC:
                d = a.AesDecryptCBC([]byte(data))
        case MODE_ECB:
                d = a.AesDecryptECB([]byte(data))
        case MODE_CFB:
                d, err = a.AesDecryptCFB([]byte(data))
        }
        return
}

// =================== CBC ======================
func (a *Aes) AesEncryptCBC(data []byte) []byte {
        data = a.pkcs5Padding(data)                         // 补全码
        bm := cipher.NewCBCEncrypter(a.block, a.key[:a.bs]) // 加密模式
        encrypted := make([]byte, len(data))                // 创建数组
        bm.CryptBlocks(encrypted, data)                     // 加密
        return encrypted
}
func (a *Aes) AesDecryptCBC(data []byte) []byte {
        bm := cipher.NewCBCDecrypter(a.block, a.key[:a.bs]) // 加密模式
        decrypted := make([]byte, len(data))                // 创建数组
        bm.CryptBlocks(decrypted, data)                     // 解密
        decrypted = a.pkcs5UnPadding(decrypted)             // 去除补全码
        return decrypted
}
func (a *Aes) pkcs5Padding(ct []byte) []byte {
        padding := a.bs - len(ct)%a.bs
        padtext := bytes.Repeat([]byte{byte(padding)}, padding)
        return append(ct, padtext...)
}
func (a *Aes) pkcs5UnPadding(data []byte) []byte {
        length := len(data)
        unpadding := int(data[length-1])
        return data[:(length - unpadding)]
}

// =================== ECB ======================
func (a *Aes) AesEncryptECB(data []byte) []byte {
        cipher, _ := aes.NewCipher(a.generateKey())
        length := (len(data) + aes.BlockSize) / aes.BlockSize
        plain := make([]byte, length*aes.BlockSize)
        copy(plain, data)
        pad := byte(len(plain) - len(data))
        for i := len(data); i < len(plain); i++ {
                plain[i] = pad
        }
        encrypted := make([]byte, len(plain))
        // 分组分块加密
        for bs, be := 0, cipher.BlockSize(); bs <= len(data); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
                cipher.Encrypt(encrypted[bs:be], plain[bs:be])
        }

        return encrypted
}
func (a *Aes) AesDecryptECB(encrypted []byte) (decrypted []byte) {
        cipher, _ := aes.NewCipher(a.generateKey())
        decrypted = make([]byte, len(encrypted))
        for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
                cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
        }

        trim := 0
        if len(decrypted) > 0 {
                trim = len(decrypted) - int(decrypted[len(decrypted)-1])
        }

        return decrypted[:trim]
}

func (a *Aes) generateKey() (genKey []byte) {
        genKey = make([]byte, 16)
        copy(genKey, a.key)
        for i := 16; i < len(a.key); {
                for j := 0; j < 16 && i < len(a.key); j, i = j+1, i+1 {
                        genKey[j] ^= a.key[i]
                }
        }
        return genKey
}

// =================== CFB ======================
func (a *Aes) AesEncryptCFB(data []byte) []byte {
        encrypted := make([]byte, aes.BlockSize+len(data))
        iv := encrypted[:aes.BlockSize]
        if _, err := io.ReadFull(rand.Reader, iv); err != nil {
                panic(err)
        }
        stream := cipher.NewCFBEncrypter(a.block, iv)
        stream.XORKeyStream(encrypted[aes.BlockSize:], data)
        return encrypted
}
func (a *Aes) AesDecryptCFB(data []byte) (d []byte, err error) {
        if len(data) < aes.BlockSize {
                err = fmt.Errorf("ciphertext too short")
                return
        }

        iv := data[:aes.BlockSize]
        data = data[aes.BlockSize:]

        stream := cipher.NewCFBDecrypter(a.block, iv)
        stream.XORKeyStream(data, data)
        d = data
        return
}

const DEFAULT_KEY = "k39sn4ldsemxoe3kdielxo7edlxdapqd"

var defaultAes, _ = NewAes(DEFAULT_KEY, MODE_CBC)

func Encrypt(data string) ([]byte, error) {
        return defaultAes.Encrypt(data)
}

func Decrypt(data string) ([]byte, error) {
        return defaultAes.Decrypt(data)
}