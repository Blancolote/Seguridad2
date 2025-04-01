// El paquete server contiene el código del servidor.
// Interactúa con el cliente mediante una API JSON/HTTP
package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"prac/pkg/api"
	"prac/pkg/store"
	"strconv"
	"strings"

	"time"
)

var currentHospital int
var currentSpecialty int

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

type Paciente struct {
	Nombre           string `json:"nombre"`
	Apellido         string `json:"apellido"`
	Fecha_nacimiento string `json:"fecha_nacimiento"`
	Sexo             string `json:"sexo"`
	Hospital         int    `json:"hospital"`
	Historial        string `json:"historial"`
	Medico           string `json:"medico"`
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

type Observaciones struct {
	Fecha_actualizacion string `json:"fecha_actualizacion"`
	Diagnostico         string `json:"diagnostico"`
	Medico              string `json:"medico"`
}

type Expediente struct {
	Medico         string          `json:"medico"`
	Observaciones  []Observaciones `json:"observaciones"`
	Fecha_creacion string          `json:"fecha_creacion"`
	Especialidad   int             `json:"especialidad"`
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

	// Construimos un mux y asociamos /api a nuestro apiHandler,
	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	// Iniciamos el servidor HTTP.
	err = http.ListenAndServe(":8080", mux)

	return err
}

// apiHandler descodifica la solicitud JSON, la despacha
// a la función correspondiente y devuelve la respuesta JSON.
func (s *server) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Decodificamos la solicitud en una estructura api.Request
	var req api.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}

	// Despacho según la acción solicitada
	var res api.Response
	switch req.Action {
	case api.ActionRegister:
		res = s.registerUser(req)
	case api.ActionLogin:
		res = s.loginUser(req)
	case api.ActionFetchData:
		res = s.fetchData(req)
	case api.ActionUpdateData:
		res = s.updateData(req)
	case api.ActionLogout:
		res = s.logoutUser(req)
	case api.ActionObtenerExpedientes:
		res = s.obtenerExpedientes(req)
	case api.ActionDarAlta:
		res = s.addPaciente(req)
	case api.ActionCrearExpediente:
		res = s.anyadirExpediente(req)
	case api.ActionModificarExpediente:
		res = s.anyadirObservaciones(req)

	default:
		res = api.Response{Success: -1, Message: "Acción desconocida"}
	}

	// Enviamos la respuesta en formato JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// generateToken crea un token único incrementando un contador interno (inseguro)
func (s *server) generateToken(expirationDuration time.Duration) (api.Token, error) {
	// Generar bytes aleatorios (32 bytes para buena entropía)
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return api.Token{}, err
	}

	// Codificar los bytes en base64 para obtener una cadena
	tokenValue := base64.URLEncoding.EncodeToString(bytes)

	// Calcular fecha de expiración
	expiresAt := time.Now().Add(expirationDuration)

	return api.Token{
		Value:     tokenValue,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *server) obtenerUltimoID(namespace string) string {
	keys, err := s.db.ListKeys(namespace)
	if err != nil {
		return "Q"
	}
	if len(keys) == 0 {
		return "1"
	}

	lastElement := string(keys[len(keys)-1])
	fmt.Println("LastElemente: ", lastElement)
	id_int, errAtoi := strconv.Atoi(lastElement)
	if errAtoi != nil {
		return "P"
	}

	id_int = id_int + 1

	id_final := strconv.Itoa(id_int)
	return id_final
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

// registerUser registra un nuevo usuario, si no existe.
// - Guardamos la contraseña en el namespace 'auth'
// - Creamos entrada vacía en 'userdata' para el usuario
func (s *server) registerUser(req api.Request) api.Response {
	// Validación básica
	if req.Username == "" || req.Password == "" || req.Apellido == "" || req.Especialidad == 0 || req.Hospital == 0 {
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}

	// Verificamos si ya existe el usuario en 'auth'
	exists, err := s.userExists(req.Username)
	if err != nil {
		return api.Response{Success: -1, Message: "Error al verificar usuario"}
	}
	if exists {
		return api.Response{Success: -1, Message: "El usuario ya existe"}
	}

	usuario := Usuario{
		Constraseña:  req.Password,
		Apellido:     req.Apellido,
		Especialidad: req.Especialidad,
		Hospital:     req.Hospital,
	}

	jsonUsuario, errJson := json.Marshal(usuario)

	if errJson != nil {
		return api.Response{Success: -1, Message: "Los datos del Json del usuario están mal"}
	}

	if err := s.db.Put("Usuarios", []byte(req.Username), []byte(jsonUsuario)); err != nil {

	}
	return api.Response{Success: 1, Message: fmt.Sprintf("Usuario %s registrado correctamente", req.Username)}
}

// loginUser valida credenciales en el namespace 'auth' y genera un token en 'sessions'.
func (s *server) loginUser(req api.Request) api.Response {
	if req.Username == "" || req.Password == "" {
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}

	// Recogemos la contraseña guardada en 'auth'
	userData, err := s.db.Get("Usuarios", []byte(req.Username))

	if err != nil {
		return api.Response{Success: -1, Message: "Usuario no encontrado"}
	}

	var datosUsuario Usuario
	errUser := json.Unmarshal(userData, &datosUsuario)
	if errUser != nil {
		return api.Response{Success: -1, Message: "Estructura del usuario"}
	}
	storedPass := datosUsuario.Constraseña
	// Comparamos
	if string(storedPass) != req.Password {
		return api.Response{Success: -1, Message: "Credenciales inválidas"}
	}

	// Generamos un nuevo token, lo guardamos en 'sessions'
	token, errGenerateToken := s.generateToken(30 * time.Minute)
	if errGenerateToken != nil {
		return api.Response{Success: -1, Message: "Error creando el Token"}
	}

	tokenJson, _ := json.Marshal(token)
	if err := s.db.Put("sessions", []byte(req.Username), []byte(tokenJson)); err != nil {
		return api.Response{Success: -1, Message: "Error al crear sesión"}
	}

	var usuario Usuario
	especialidadalactual, err := s.db.Get("Usuarios", []byte(req.Username))
	errEsp := json.Unmarshal(especialidadalactual, &usuario)

	if errEsp != nil {
		return api.Response{Success: -1, Message: "Erro al convertir hospital a struct"}
	}

	currentSpecialty = usuario.Especialidad
	currentHospital = usuario.Hospital
	fmt.Println("Token en el login ", token)
	return api.Response{Success: 1, Message: "Login exitoso", Token: token}
}

// Obtener expedientes de la especialidad del médico
func (s *server) obtenerExpedientes(req api.Request) api.Response {
	if req.DNI == "" || req.Token.Value == "" {
		return api.Response{Success: -1, Message: "Faltan datos"}
	}
	if !s.isTokenValid(req.Token, req.Username) {
		return api.Response{Success: 0, Message: "Error en las credenciales: Token inválido o caducado"}
	}

	historial, err_hist := s.db.Get("Historiales", []byte(req.DNI))

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
		var expedienteStruct Expediente
		json.Unmarshal(expediente, &expedienteStruct)

		info_expedientes = append(info_expedientes, expediente)
	}

	if err != nil {
		return api.Response{Success: -1, Message: "No existe dicha especialidad"}
	}

	return api.Response{Success: 1, Message: "Expedientes obtenidos", Expedientes: info_expedientes}
}

func (s *server) addPaciente(req api.Request) api.Response {
	if req.DNI == "" || req.Nombre == "" || req.Apellido == "" || req.Fecha == "" || req.Username == "" || req.Sexo == "" || req.Token.Value == "" {
		return api.Response{Success: -1, Message: "Faltan datos del paciente"}
	}

	if !s.isTokenValid(req.Token, req.Username) {
		return api.Response{Success: 0, Message: "Error en las credenciales: Token inválido o caducado"}
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

	errHist := s.db.Put("Historiales", []byte(req.DNI), []byte(historial_json))

	if errHist != nil {
		return api.Response{Success: -1, Message: "Error creando historial en la base de datos"}
	}

	paciente := Paciente{
		Nombre:           req.Nombre,
		Apellido:         req.Apellido,
		Fecha_nacimiento: req.Fecha,
		Hospital:         currentHospital,
		Sexo:             req.Sexo,
		Medico:           req.Username,
		Historial:        req.DNI,
	}

	paciente_json, errJson := json.Marshal(paciente)

	if errJson != nil {
		return api.Response{Success: -1, Message: "No pueden convertirse los datos a json"}
	}

	err := s.db.Put("Pacientes", []byte(req.DNI), []byte(paciente_json))

	if err != nil {
		return api.Response{Success: -1, Message: "Error creando al paciente"}
	}

	return api.Response{Success: 1, Message: "Usuario creado"}
}

// fetchData verifica el token y retorna el contenido del namespace 'userdata'.
func (s *server) fetchData(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token.Value == "" {
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Token, req.Username) {
		return api.Response{Success: 0, Message: "Token inválido o sesión expirada"}
	}

	// Obtenemos los datos asociados al usuario desde 'userdata'
	rawData, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		return api.Response{Success: -1, Message: "Error al obtener datos del usuario"}
	}

	return api.Response{
		Success: 1,
		Message: "Datos privados de " + req.Username,
		Data:    string(rawData),
	}
}

// updateData cambia el contenido de 'userdata' (los "datos" del usuario)
// después de validar el token.
func (s *server) updateData(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token.Value == "" {
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Token, req.Username) {
		return api.Response{Success: 0, Message: "Token inválido o sesión expirada"}
	}

	// Escribimos el nuevo dato en 'userdata'
	if err := s.db.Put("userdata", []byte(req.Username), []byte(req.Data)); err != nil {
		return api.Response{Success: -1, Message: "Error al actualizar datos del usuario"}
	}

	return api.Response{Success: 1, Message: "Datos de usuario actualizados"}
}

func (s *server) anyadirObservaciones(req api.Request) api.Response {
	if req.Username == "" || req.Token.Value == "" || req.Fecha == "" || req.Diagnostico == "" || req.ID == 0 {
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Token, req.Username) {
		return api.Response{Success: 0, Message: "Token inválido o sesión expirada"}
	}

	observacion := Observaciones{
		Fecha_actualizacion: req.Fecha,
		Diagnostico:         req.Diagnostico,
	}
	expediente, err := s.db.Get("Expedientes", []byte(string(req.ID)))

	if err != nil {
		return api.Response{Success: -1, Message: "No existe un expediente con DNI: %"}
	}
	var expedienteStruct Expediente
	errStruct := json.Unmarshal(expediente, &expedienteStruct)

	if errStruct != nil {
		return api.Response{Success: -1, Message: "Error al convertir a estructura el expediente"}
	}

	observaciones_originales := expedienteStruct.Observaciones

	observaciones := append(observaciones_originales, observacion)
	expedienteModificado := Expediente{
		Medico:         req.Username,
		Observaciones:  observaciones,
		Fecha_creacion: expedienteStruct.Fecha_creacion,
		Especialidad:   expedienteStruct.Especialidad,
	}

	expedienteModificadoJson, errJson := json.Marshal(expedienteModificado)

	if errJson != nil {
		return api.Response{Success: -1, Message: "Error al convertir expediente a Json"}
	}
	s.db.Put("Expedientes", []byte(string(req.ID)), []byte(expedienteModificadoJson))

	return api.Response{Success: 1, Message: "Expediente modificado correctamente"}
}

func (s *server) anyadirExpediente(req api.Request) api.Response {
	if req.Username == "" || req.Diagnostico == "" || req.DNI == "" || req.Token.Value == "" {
		return api.Response{Success: -1, Message: "Faltan credenciales para añadir expedientes"}
	}

	if !s.isTokenValid(req.Token, req.Username) {
		return api.Response{Success: 0, Message: "Token inválido o sesión expirada"}
	}

	fecha := time.Now()
	fechaStr := fecha.Format(time.DateOnly)

	var observaciones []Observaciones

	observacion := Observaciones{
		Fecha_actualizacion: fechaStr,
		Diagnostico:         req.Diagnostico,
		Medico:              req.Username,
	}
	ultimoId := s.obtenerUltimoID("Expedientes")
	observaciones = append(observaciones, observacion)

	expediente := Expediente{
		Medico:         req.Username,
		Observaciones:  observaciones,
		Fecha_creacion: fechaStr,
		Especialidad:   currentSpecialty,
	}

	expedieteJson, errJson := json.Marshal(expediente)
	if errJson != nil {
		return api.Response{Success: -1, Message: "Error convirtiendo a json el expediente"}
	}

	s.db.Put("Expedientes", []byte(ultimoId), []byte(expedieteJson))

	historialPaciente, errget := s.db.Get("Historiales", []byte(string(req.DNI)))
	if errget != nil {
		return api.Response{Success: -1, Message: "Error al obtener el historial del paciente"}
	}

	var historialSruct Historial
	errStructHistorial := json.Unmarshal(historialPaciente, &historialSruct)
	if errStructHistorial != nil {
		return api.Response{Success: -1, Message: "Error al convertir el historial a struct"}
	}
	expedientesOriginales := historialSruct.Expedientes

	ultimoIdInt, erratoi := strconv.Atoi(ultimoId)
	if erratoi != nil {
		return api.Response{Success: -1, Message: "Error al convertir el id del expediente en int"}
	}
	expedientes := append(expedientesOriginales, ultimoIdInt)

	nuevoHistorial := Historial{
		Fecha_creacion: fechaStr,
		Expedientes:    expedientes,
	}

	nuevoHistorialJson, erroerrJsonHistorial := json.Marshal(nuevoHistorial)
	if erroerrJsonHistorial != nil {
		return api.Response{Success: -1, Message: "Error al convertir el historial en json"}
	}

	s.db.Put("Historiales", []byte(req.DNI), []byte(nuevoHistorialJson))

	return api.Response{Success: 1, Message: "Expediente creado y añadido al historial correctamente"}
}

// logoutUser borra la sesión en 'sessions', invalidando el token.
func (s *server) logoutUser(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token.Value == "" {
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Token, req.Username) {
		return api.Response{Success: 0, Message: "Token inválido o sesión expirada"}
	}

	// Borramos la entrada en 'sessions'
	if err := s.db.Delete("sessions", []byte(req.Username)); err != nil {
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

func (s *server) isTokenValid(token api.Token, username string) bool {
	tokenUser, err := s.db.Get("sessions", []byte(username))
	if err != nil {
		return false
	}

	var tokenComprobar api.Token
	errJSon := json.Unmarshal(tokenUser, &tokenComprobar)

	if errJSon != nil || !time.Now().Before(token.ExpiresAt) || token.Value != tokenComprobar.Value {
		return false
	}

	return true
}
