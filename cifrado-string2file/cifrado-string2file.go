package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	key := obtenerSHA256("Clave")
	iv := obtenerSHA256("<inicializar>")

	textoEnClaro := "Texto en claro"
	nombreArchivoDatos := "datos.zip.enc"

	//----------CIFRADO--------------
	cifrarStringEnArchivo(textoEnClaro, nombreArchivoDatos, key, iv)

	//----------DESCIFRADO-----------
	textoEnClaroDescifrado := descifrarArchivoEnString(nombreArchivoDatos, key, iv)

	//----------Comprobación-----------
	if textoEnClaroDescifrado == textoEnClaro {
		fmt.Println("Cifrado realizado correctamente")
	} else {
		fmt.Println("Algo ha fallado con el cifrado")
	}
}

func descifrarArchivoEnString(nombreArchivoDatos string, key []byte, iv []byte) string {
	archivoOrigenComprimidoCifrado, err := os.Open(nombreArchivoDatos)
	check(err)

	var bufferDeBytesParaDescifraryDescomprimir bytes.Buffer

	var lectorConDescifrado cipher.StreamReader
	lectorConDescifrado.S, err = obtenerAESconCTR(key, iv)
	lectorConDescifrado.R = archivoOrigenComprimidoCifrado
	check(err)

	lectorConDescifradoDescompresion, err := zlib.NewReader(lectorConDescifrado)
	check(err)

	_, err = io.Copy(&bufferDeBytesParaDescifraryDescomprimir, lectorConDescifradoDescompresion)
	check(err)
	archivoOrigenComprimidoCifrado.Close()

	textoEnClaroDescifrado := bufferDeBytesParaDescifraryDescomprimir.String()
	return textoEnClaroDescifrado
}

func cifrarStringEnArchivo(textoEnClaro string, nombreArchivoDatos string, key []byte, iv []byte) {
	lectorTextoEnClaro := strings.NewReader(textoEnClaro)

	archivoDestinoComprimidoyCifrado, err := os.Create(nombreArchivoDatos)
	check(err)

	var escritorConCifrado cipher.StreamWriter
	escritorConCifrado.S, err = obtenerAESconCTR(key, iv)
	escritorConCifrado.W = archivoDestinoComprimidoyCifrado
	check(err)

	escritorConCompresionyCifrado := zlib.NewWriter(escritorConCifrado)

	_, err = io.Copy(escritorConCompresionyCifrado, lectorTextoEnClaro)
	check(err)

	escritorConCompresionyCifrado.Close()
	archivoDestinoComprimidoyCifrado.Close()
}

func obtenerAESconCTR(key []byte, iv []byte) (cipher.Stream, error) {
	//Si la clave no es de 128 o 256 bits => Error
	if !(len(key) == 16 || len(key) == 32) {
		return nil, errors.New("la clave no es de 128 o 256 bits")
	}

	CifradorDeUnBloque, err := aes.NewCipher(key)
	check(err)
	CifradorVariosBloquesConCTR := cipher.NewCTR(CifradorDeUnBloque, iv[:16])
	return CifradorVariosBloquesConCTR, nil
}

func obtenerSHA256(Clave string) []byte {
	h := sha256.New()
	h.Reset()
	_, err := h.Write([]byte(Clave))
	check(err)
	retorno := h.Sum(nil)
	return retorno
}
