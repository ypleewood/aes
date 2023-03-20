# aes
对称加密AES实现

# 安装
go get github.com/ypleewood/aes

# 快速开始
```go 
str := "Hello World"

encStr,_ := aes.Encode(rawStr)
decStr, _ := aes.Decode(encStr)
```
