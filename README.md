Export Bytom Functions to Java
==============================

In order to write a Kotlin implementation of [Bytom](https://github.com/Bytom/bytom), I have to export some of Go functions to Java, and used them in Kotlin.
Otherwise, it's almost impossible to interact with Bytom's node in a language other than Go, since the generated keys, data, encrypted messages are probably different, can't be understand by each other.

The Kotlin implementation is here: <https://github.com/freewind/bytom.kt>

```
brew install go
brew install mvn

go get
go build -buildmode=c-shared -o ./src/main/resources/darwin/libbytom-exports.dylib ./go/bytom-exports.go
mvn install
```

You should be able to compile the project "bytom.kt".