// El paquete server contiene el código del servidor.
// Interactúa con el cliente mediante una API JSON/HTTP
package server

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"prac/pkg/api"
	"prac/pkg/store"
	"strconv"
	"strings"

	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/dgrijalva/jwt-go"
)

var currentHospital string
var currentSpecialty string

// server encapsula el estado de nuestro servidor
type server struct {
	db                 store.Store // base de datos
	log                *log.Logger // logger para mensajes de error e información
	tokenCounter       int64       // contador para generar tokens
	contadorIDPaciente int64
	contadorIDMedico   int64
}

type Usuario struct {
	Constraseña  string `json:"contraseña"`
	Apellido     string `json:"apellido"`
	Especialidad int    `json:"especialidad"`
	Hospital     int    `json:"hospital"`
}

type Hospital struct {
	Nombre string `json:"nombre"`
}

type Especialidad struct {
	Nombre string `json:"nombre"`
}

type Historial struct {
	Fecha_creacion string `json:"fecha_creacion"`
	Expedientes    []int  `json:"expedientes"` //tener en cuenta que para actualizarlos hay que coger la lista existente y añadirle uno nuevo
}

// ------------------EMPIEZO CON HTTPS MODIFICACIONES---------------------------

type user struct { //name se usará como id en los namespaces
	Hash         []byte
	Salt         []byte
	Private      string
	Public       string
	Apellido     string `json:"apellido,omitempty"`
	Especialidad string `json:"especialidad,omitempty"`
	Hospital     string `json:"hospital,omitempty"`
}

func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func (s *server) comprobarHospEsp(namespace string, id int) bool {
	id_int := strconv.Itoa(id)
	_, err := s.db.Get(namespace, []byte(id_int))
	if err != nil {
		return false
	}
	return true
}

// Run inicia la base de datos y arranca el servidor HTTP.
func Run() error {
	// Abrimos la base de datos usando el motor bbolt
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error abriendo base de datos: %v", err)
	}

	// Creamos nuestro servidor con su logger con prefijo 'srv'
	srv := &server{
		db:  db,
		log: log.New(os.Stdout, "[srv] ", log.LstdFlags),
	}

	// Al terminar, cerramos la base de datos
	defer srv.db.Close()

	http.HandleFunc("/", srv.handler) // asignamos un handler global

	// escuchamos el puerto 10443 con https y comprobamos el error
	// Para generar certificados autofirmados con openssl usar:
	//    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=ES/ST=Alicante/L=Alicante/O=UA/OU=Org/CN=www.ua.com"
	chk(http.ListenAndServeTLS(":10443", "cert.pem", "key.pem", nil))

	return err
}

// apiHandler descodifica la solicitud JSON, la despacha
// a la función correspondiente y devuelve la respuesta JSON.
func (s *server) handler(w http.ResponseWriter, req *http.Request) {

	//if req.Method != http.MethodPost {
	//http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
	//return
	//}
	req.ParseForm()
	w.Header().Set("Content-Type", "application/json")

	switch req.Form.Get("cmd") {
	case "register":
		res := s.registerUser(req)
		response(w, res)
	case "login":
		res := s.loginUser(req)
		response(w, res)
	case "addPaciente":
		res := s.addPaciente(req)
		response(w, res)
	case "verHistorialPaciente":
		res := s.obtenerExpedientes(req)
		response(w, res)
	case "crearExpediente":
		res := s.anyadirExpediente(req)
		response(w, res)
	case "logout":
		res := s.logoutUser(req)
		response(w, res)
	case "modificarExpediente":
		res := s.anyadirObservaciones(req)
		response(w, res)
	}

}

func (s *server) obtenerUltimoID(namespace string) (string, error) {
	keys, err := s.db.ListKeys(namespace)
	if err != nil {
		return "", err
	}

	if len(keys) == 0 {
		return "1", nil
	}

	// Convertir todas las keys a números y encontrar el máximo
	maxID := 0
	for _, key := range keys {
		id, err := strconv.Atoi(string(key))
		if err == nil && id > maxID {
			maxID = id
		}
	}

	return strconv.Itoa(maxID + 1), nil
}

func (s *server) obtenerIdHospital(nombre string) int {
	listaKeys, err := s.db.ListKeys("Hospitales")
	if err != nil {
		return -1
	}
	var key int
	for i := 0; i < len(listaKeys); i++ {
		hospitalJson, errget := s.db.Get("Hospitales", []byte(listaKeys[i]))
		if errget != nil {
			return -1
		}

		var hospitalStruct Hospital

		errStruct := json.Unmarshal(hospitalJson, &hospitalStruct)
		if errStruct != nil {
			return -1
		}
		if hospitalStruct.Nombre == nombre {
			key = i + 1
			break
		}
	}
	return key
}

func response(w io.Writer, res api.Response) {
	r := res                       // formateamos respuesta
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

// función para comprimir
func compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	w.Write(data)           // escribimos los datos
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

// función para descomprimir
func decompress(data []byte) []byte {
	var b bytes.Buffer // b contendrá los datos descomprimidos

	r, err := zlib.NewReader(bytes.NewReader(data)) // lector descomprime al leer

	chk(err)         // comprobamos el error
	io.Copy(&b, r)   // copiamos del descompresor (r) al buffer (b)
	r.Close()        // cerramos el lector (buffering)
	return b.Bytes() // devolvemos los datos descomprimidos
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// Función de re
func (s *server) registerUser(req *http.Request) api.Response {
	// Validación básica
	if req.Form.Get("username") == "" || req.Form.Get("password") == "" || req.Form.Get("apellido") == "" || req.Form.Get("especialidad") == "0" || req.Form.Get("hospital") == "0" {
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}

	// Verificamos si ya existe el usuario en 'auth'
	exists, err := s.userExists(req.Form.Get("Username"))
	if err != nil {
		return api.Response{Success: -1, Message: "No sé"}
	}
	if exists {
		return api.Response{Success: -1, Message: "El usuario ya existe"}
	}

	name := req.Form.Get("username")               // nombre
	salt := make([]byte, 16)                       // sal (16 bytes == 128 bits)
	rand.Read(salt)                                // la sal es aleatoria               // reservamos mapa de datos de usuario
	private := req.Form.Get("prikey")              // clave privada
	public := req.Form.Get("pubkey")               // clave pública
	password := decode64(req.Form.Get("password")) // contraseña (keyLogin)

	hash, _ := scrypt.Key(password, salt, 16384, 8, 1, 32)
	u := user{
		Salt:         salt,
		Hash:         hash,
		Private:      private,
		Public:       public,
		Apellido:     req.Form.Get("apellidos"),
		Hospital:     req.Form.Get("hospital"),
		Especialidad: req.Form.Get("especialidad"),
	}
	u_json, _ := json.Marshal(u)

	if err := s.db.Put("Usuarios", []byte(name), []byte(u_json)); err != nil {
		return api.Response{Success: -1, Message: "Error al crear el usuario"}
	}

	return api.Response{Success: 1, Message: "Usuario creado"}
}

// loginUser valida credenciales en el namespace 'auth' y genera un token en 'sessions'.
func (s *server) loginUser(req *http.Request) api.Response {
	if req.Form.Get("username") == "" || req.Form.Get("password") == "" {
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}

	// Se comprueba si el usuario existe
	userData, err := s.db.Get("Usuarios", []byte(req.Form.Get("username")))

	if err != nil {
		return api.Response{Success: -1, Message: "Usuario no encontrado"}
	}

	var datosUsuario user
	errUser := json.Unmarshal(userData, &datosUsuario)
	if errUser != nil {
		return api.Response{Success: -1, Message: "Fallo en la estructura del usuario"}
	}

	password := decode64(req.Form.Get("password")) // obtenemos la contraseña
	hash, _ := scrypt.Key(password, datosUsuario.Salt, 16384, 8, 1, 32)

	if bytes.Compare(datosUsuario.Hash, hash) != 0 {
		return api.Response{Success: -1, Message: "Contraseña incorrecta"}
	}

	token := crearToken(req.Form.Get("username"), 10)

	currentSpecialty = datosUsuario.Especialidad
	currentHospital = datosUsuario.Hospital

	return api.Response{Success: 1, Message: "Login exitoso", Token: token}
}

// Obtener expedientes de la especialidad del médico
func (s *server) obtenerExpedientes(req *http.Request) api.Response {

	if req.Form.Get("dni") == "" || req.Form.Get("token") == "" {
		return api.Response{Success: -1, Message: "Faltan datos"}
	}
	_, ok := isTokenValid(req.Form.Get("token"), req.Form.Get("username"))

	if !ok {
		return api.Response{Success: 0, Message: "Error en las credenciales: Token inválido o caducado"}
	}

	historial, err_hist := s.db.Get("Historiales", []byte(req.Form.Get("dni")))

	if err_hist != nil {
		return api.Response{Success: -1, Message: "El Dni introducido es incorrecto"}
	}

	var historial_json Historial
	err := json.Unmarshal(historial, &historial_json)
	lista_expedientes := historial_json.Expedientes

	var info_expedientes [][]byte
	for i := 0; i < len(lista_expedientes); i++ {
		expedienteKey := strconv.Itoa(lista_expedientes[i]) // Convertir int a string
		expediente, errExp := s.db.Get("Expedientes", []byte(expedienteKey))
		if errExp != nil {
			return api.Response{Success: -1, Message: "Los expedientes del paciente son incorrectos"}
		}

		// Convertimos el JSON a un mapa para modificarlo
		var expedienteStruct api.Expediente
		json.Unmarshal(expediente, &expedienteStruct)

		info_expedientes = append(info_expedientes, expediente)
	}

	if err != nil {
		return api.Response{Success: -1, Message: "No existe dicha especialidad"}
	}
	return api.Response{Success: 1, Message: "Expedientes obtenidos", Expedientes: info_expedientes}
}

func (s *server) addPaciente(req *http.Request) api.Response {

	if req.Form.Get("dni") == "" || req.Form.Get("nom_Paciente") == "" || req.Form.Get("apellido") == "" || req.Form.Get("fecha") == "" || req.Form.Get("username") == "" || req.Form.Get("sexo") == "" || req.Form.Get("token") == "" {
		return api.Response{Success: -1, Message: "Faltan datos del paciente"}
	}

	_, ok := isTokenValid(req.Form.Get("token"), req.Form.Get("username"))
	if !ok {
		return api.Response{Success: 0, Message: "Error en las credenciales: Token inválido o caducado"}
	}

	_, errDNI := s.db.Get("Pacientes", []byte(req.Form.Get("dni")))
	if errDNI == nil {
		return api.Response{Success: -1, Message: "El paciente ya existe"}
	}

	fecha := time.Now()
	fechaStr := fecha.Format(time.DateOnly)
	lista_vacia_Expedientes := []int{}
	historial := Historial{
		Fecha_creacion: fechaStr,
		Expedientes:    lista_vacia_Expedientes,
	}

	historial_json, errJsonHist := json.Marshal(historial)

	if errJsonHist != nil {
		return api.Response{Success: -1, Message: "Error creando json de historial"}
	}

	errHist := s.db.Put("Historiales", []byte(req.Form.Get("dni")), []byte(historial_json))

	if errHist != nil {
		return api.Response{Success: -1, Message: "Error creando historial en la base de datos"}
	}

	paciente := api.Paciente{
		Nombre:           req.Form.Get("nombre"),
		Apellido:         req.Form.Get("apellido"),
		Fecha_nacimiento: req.Form.Get("fecha"),
		Hospital:         currentHospital,
		Sexo:             req.Form.Get("sexo"),
		Medico:           req.Form.Get("username"),
		Historial:        req.Form.Get("dni"),
	}

	paciente_json, errJson := json.Marshal(paciente)

	if errJson != nil {
		return api.Response{Success: -1, Message: "No pueden convertirse los datos a json"}
	}

	err := s.db.Put("Pacientes", []byte(req.Form.Get("dni")), []byte(paciente_json))

	if err != nil {
		return api.Response{Success: -1, Message: "Error creando al paciente"}
	}

	return api.Response{Success: 1, Message: "Usuario creado"}
}

func (s *server) anyadirObservaciones(req *http.Request) api.Response {
	if req.Form.Get("username") == "" || req.Form.Get("token") == "" || req.Form.Get("fecha") == "" || req.Form.Get("diagnostico") == "" || req.Form.Get("id") == "" || req.Form.Get("tratamiento") == "" {
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}
	_, ok := isTokenValid(req.Form.Get("token"), req.Form.Get("username"))
	if !ok {
		return api.Response{Success: 0, Message: "Token inválido o sesión expirada"}
	}

	observacion := api.Observaciones{
		Fecha_actualizacion: req.Form.Get("fecha"),
		Diagnostico:         req.Form.Get("diagnostico"),
		Tratamiento:         req.Form.Get("tratamiento"),
	}
	expediente, err := s.db.Get("Expedientes", []byte(string(req.Form.Get("id"))))

	if err != nil {
		return api.Response{Success: -1, Message: "No existe un expediente con ID: %"}
	}
	var expedienteStruct api.Expediente
	errStruct := json.Unmarshal(expediente, &expedienteStruct)

	if errStruct != nil {
		return api.Response{Success: -1, Message: "Error al convertir a estructura el expediente"}
	}

	observaciones_originales := expedienteStruct.Observaciones

	observaciones := append(observaciones_originales, observacion)
	expedienteModificado := api.Expediente{
		ID:            expedienteStruct.ID,
		Username:      req.Form.Get("username"),
		Observaciones: observaciones,
		FechaCreacion: expedienteStruct.FechaCreacion,
		Especialidad:  expedienteStruct.Especialidad,
	}

	expedienteModificadoJson, errJson := json.Marshal(expedienteModificado)

	if errJson != nil {
		return api.Response{Success: -1, Message: "Error al convertir expediente a Json"}
	}
	s.db.Put("Expedientes", []byte(string(req.Form.Get("id"))), []byte(expedienteModificadoJson))
	fmt.Println("Expediente modificado correctamente")
	return api.Response{Success: 1, Message: "Expediente modificado correctamente"}
}

func (s *server) anyadirExpediente(req *http.Request) api.Response {
	if req.Form.Get("username") == "" || req.Form.Get("diagnostico") == "" || req.Form.Get("dni") == "" || req.Form.Get("token") == "" {
		return api.Response{Success: -1, Message: "Faltan credenciales para añadir expedientes"}
	}

	_, ok := isTokenValid(req.Form.Get("token"), req.Form.Get("username"))
	if !ok {
		return api.Response{Success: 0, Message: "Token inválido o sesión expirada"}
	}

	fecha := time.Now().Format("2006-01-02")

	ultimoId, err := s.obtenerUltimoID("Expedientes")
	if err != nil {
		return api.Response{Success: -1, Message: "Error al generar ID de expediente"}
	}

	ultimoIdInt, err := strconv.Atoi(ultimoId)
	if err != nil {
		return api.Response{Success: -1, Message: "Error en formato de ID"}
	}

	expediente := api.Expediente{
		ID:       ultimoId,
		Username: req.Form.Get("username"),
		Observaciones: []api.Observaciones{
			{
				Fecha_actualizacion: fecha,
				Diagnostico:         req.Form.Get("diagnostico"),
				Medico:              req.Form.Get("username"),
			},
		},
		FechaCreacion: fecha,
		Especialidad:  currentSpecialty,
	}
	expedienteJson, errJson := json.Marshal(expediente)
	if errJson != nil {
		return api.Response{Success: -1, Message: "Error convirtiendo a json el expediente"}
	}

	if err := s.db.Put("Expedientes", []byte(ultimoId), expedienteJson); err != nil {
		return api.Response{Success: -1, Message: "Error guardando expediente"}
	}

	historialPaciente, errget := s.db.Get("Historiales", []byte(string(req.Form.Get("dni"))))
	if errget != nil {
		return api.Response{Success: -1, Message: "Error al obtener el historial del paciente"}
	}

	var historialStruct Historial
	errStructHistorial := json.Unmarshal(historialPaciente, &historialStruct)
	if errStructHistorial != nil {
		return api.Response{Success: -1, Message: "Error al convertir el historial a struct"}
	}
	expedientesOriginales := historialStruct.Expedientes

	ultimoIdInt, erratoi := strconv.Atoi(ultimoId)
	if erratoi != nil {
		return api.Response{Success: -1, Message: "Error al convertir el id del expediente en int"}
	}
	expedientes := append(expedientesOriginales, ultimoIdInt)

	found := false
	for _, id := range historialStruct.Expedientes {
		if id == ultimoIdInt {
			found = true
			break
		}
	}

	if !found {
		historialStruct.Expedientes = append(historialStruct.Expedientes, ultimoIdInt)
	}

	nuevoHistorial := Historial{
		Fecha_creacion: fecha,
		Expedientes:    expedientes,
	}

	nuevoHistorialJson, erroerrJsonHistorial := json.Marshal(nuevoHistorial)
	if erroerrJsonHistorial != nil {
		return api.Response{Success: -1, Message: "Error al convertir el historial en json"}
	}

	if err := s.db.Put("Historiales", []byte(req.Form.Get("dni")), nuevoHistorialJson); err != nil {
		return api.Response{Success: -1, Message: "Error al guardar historial actualizado"}
	}

	return api.Response{Success: 1, Message: "Expediente creado y añadido al historial correctamente"}
}

// logoutUser borra la sesión en 'sessions', invalidando el token.
func (s *server) logoutUser(req *http.Request) api.Response {
	// Chequeo de credenciales
	if req.Form.Get("username") == "" || req.Form.Get("token") == "" {
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}
	_, ok := isTokenValid(req.Form.Get("token"), req.Form.Get("username"))
	if !ok {
		return api.Response{Success: 0, Message: "Token inválido o sesión expirada"}
	}

	// YA NO HACE FALTA
	if err := s.db.Delete("sessions", []byte(req.Form.Get("username"))); err != nil {
		return api.Response{Success: -1, Message: "Error al cerrar sesión"}
	}

	return api.Response{Success: 1, Message: "Sesión cerrada correctamente"}
}

// userExists comprueba si existe un usuario con la clave 'username'
// en 'auth'. Si no se encuentra, retorna false.
func (s *server) userExists(username string) (bool, error) {
	_, err := s.db.Get("auth", []byte(username))
	if err != nil {
		// Si no existe namespace o la clave:
		if strings.Contains(err.Error(), "bucket no encontrado: auth") {
			return false, nil
		}
		if err.Error() == "clave no encontrada: "+username {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func getSecretoJwt() []byte {
	return []byte("mi-secreto")
}

func crearToken(usuario string, minutos int) string {
	//Tiempo de expiración
	Hours := 0
	Mins := minutos
	Sec := 0

	Claim := Payload{
		usuario,
		time.Now().Local().Add(
			time.Hour*time.Duration(Hours) +
				time.Minute*time.Duration(Mins) +
				time.Second*time.Duration(Sec)).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claim)

	mySecret := getSecretoJwt()
	signedToken, err := token.SignedString(mySecret)
	chk(err)

	return signedToken
}

func isTokenValid(receivedToken string, username string) (*Payload, bool) {
	token, _ := jwt.ParseWithClaims(receivedToken, &Payload{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Methodo de firma erroneo: %v", token.Header["alg"])
		}

		return getSecretoJwt(), nil
	})

	claim, ok := token.Claims.(*Payload)
	fmt.Println(claim.Id)
	if ok && token.Valid {
		return claim, true
	}

	if claim.Id != username {
		return claim, false
	}

	return claim, false
}

type Payload struct {
	Id        string `json:"jti,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

func (c Payload) Valid() error {
	vErr := new(jwt.ValidationError)
	now := jwt.TimeFunc().Unix()

	if now > c.ExpiresAt {
		delta := time.Unix(now, 0).Sub(time.Unix(c.ExpiresAt, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= jwt.ValidationErrorExpired

		return vErr
	} else {
		return nil
	}

}
