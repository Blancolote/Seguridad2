package client

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"prac/pkg/api"
	"prac/pkg/ui"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/mdp/qrterminal"
	"github.com/nsf/termbox-go"
	"golang.org/x/term"
)

var resp struct {
	Success     int      `json:"success"`
	Message     string   `json:"message"`
	Token       string   `json:"token"`
	Expedientes [][]byte `json:"expedientes,omitempty"`
	Data        string   `json:"data,omitempty"`
	TokenOTP    string   `json:"tokenOTP,omitempty"`
}

// client estructura interna no exportada que controla
// el estado de la sesión (usuario, token) y logger.
type client struct {
	log              *log.Logger
	httpCliente      *http.Client
	currentUser      string
	authToken        string
	currentSpecialty string //nuevo
	currentHospital  string //nuevo
	currentDNI       string
	TokenOTP         string
}

const QR_FOLDER = "temp/qrcodes"

func chk(e error) {
	if e != nil {
		panic(e)
	}
}
func encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

func decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}

// función para comprimir
func compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	w.Write(data)           // escribimos los datos
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// Run es la única función exportada de este paquete.
// Crea un client interno y ejecuta el bucle principal.
func Run() {
	// Creamos un logger con prefijo 'cli' para identificar
	// los mensajes en la consola.
	c := &client{
		log: log.New(os.Stdout, "[cli] ", log.LstdFlags),
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	c.httpCliente = &http.Client{Transport: tr}

	c.runLoop()
}

// runLoop maneja la lógica del menú principal.
// Si NO hay usuario logueado, se muestran ciertas opciones;
// si SÍ hay usuario logueado, se muestran otras.
func (c *client) runLoop() {

	for {
		ui.ClearScreen()

		// Construimos un título que muestre el usuario logueado, si lo hubiera.
		var title string
		if c.currentUser == "" {
			title = "Menú"
		} else {
			title = fmt.Sprintf("Menú (%s)", c.currentUser)
		}

		// Generamos las opciones dinámicamente, según si hay un login activo.
		var options []string
		if c.currentUser == "" {
			// Usuario NO logueado: Registro, Login, Salir
			options = []string{
				"Registrar usuario",
				"Iniciar sesión",
				"Salir",
			}
		} else {
			// Usuario logueado: Ver datos, Actualizar datos, Logout, Salir
			options = []string{
				"Dar de alta paciente",
				"Ver historial del paciente",
				"Cerrar sesión",
				"Salir",
			}
		}

		// Mostramos el menú y obtenemos la elección del usuario.
		choice := ui.PrintMenu(title, options)

		// Hay que mapear la opción elegida según si está logueado o no.
		if c.currentUser == "" {
			// Caso NO logueado
			switch choice {
			case 1:
				c.registerUser()
			case 2:
				c.loginUser()
			case 3:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		} else {
			// Caso logueado
			switch choice {
			case 1:
				c.darAltaPaciente()
			case 2:
				c.verHistorialPaciente()
			case 3:
				c.logoutUser()
			case 4:
				c.cleanupQRFolder() // Limpiar carpeta de QR
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		}

		// Pausa para que el usuario vea resultados.
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

func GenerateComplexPassword(length int) (string, error) {
	if length < 8 {
		length = 8 // Mínimo recomendado para seguridad
	}

	// Definimos los conjuntos de caracteres
	lowercase := "abcdefghijklmnopqrstuvwxyz"
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers := "0123456789"
	symbols := "!@#$%^&*()-_=+[]{}|;:,.<>?"

	// Aseguramos que hay al menos un carácter de cada tipo
	password := make([]byte, length)

	// Primer carácter minúscula
	randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(lowercase))))
	if err != nil {
		return "", err
	}
	password[0] = lowercase[randomIndex.Int64()]

	// Segundo carácter mayúscula
	randomIndex, err = rand.Int(rand.Reader, big.NewInt(int64(len(uppercase))))
	if err != nil {
		return "", err
	}
	password[1] = uppercase[randomIndex.Int64()]

	// Tercer carácter número
	randomIndex, err = rand.Int(rand.Reader, big.NewInt(int64(len(numbers))))
	if err != nil {
		return "", err
	}
	password[2] = numbers[randomIndex.Int64()]

	// Cuarto carácter símbolo
	randomIndex, err = rand.Int(rand.Reader, big.NewInt(int64(len(symbols))))
	if err != nil {
		return "", err
	}
	password[3] = symbols[randomIndex.Int64()]

	// Caracteres restantes aleatorios de todos los conjuntos
	allChars := lowercase + uppercase + numbers + symbols
	for i := 4; i < length; i++ {
		randomIndex, err = rand.Int(rand.Reader, big.NewInt(int64(len(allChars))))
		if err != nil {
			return "", err
		}
		password[i] = allChars[randomIndex.Int64()]
	}

	// Mezclamos la contraseña de manera criptográficamente segura
	// en lugar de usar math/rand.Perm()
	shuffled := make([]byte, length)
	copy(shuffled, password)

	// Fisher-Yates shuffle con crypto/rand
	for i := length - 1; i > 0; i-- {
		// Genera un índice aleatorio entre 0 e i (inclusive)
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}

		// Intercambia los elementos en las posiciones i y j
		shuffled[i], shuffled[j.Int64()] = shuffled[j.Int64()], shuffled[i]
	}

	return string(shuffled), nil
}

// PasswordStrength evalúa la fortaleza de una contraseña y devuelve una calificación descriptiva
func PasswordStrength(password string) string {
	score := 0

	// Longitud
	if len(password) >= 12 {
		score += 2
	} else if len(password) >= 8 {
		score += 1
	}

	// Complejidad
	if strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		score++
	}
	if strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
		score++
	}
	if strings.ContainsAny(password, "0123456789") {
		score++
	}
	if strings.ContainsAny(password, "!@#$%^&*()-_=+[]{}|;:,.<>?") {
		score++
	}

	if score >= 6 {
		return "Muy fuerte"
	} else if score >= 4 {
		return "Fuerte"
	} else if score >= 3 {
		return "Media"
	} else {
		return "Debil"
	}
}
func ReadPasswordWithLiveStrength() (string, error) {
	// Al inicio de tu programa

	err := termbox.Init()
	if err != nil {
		return "", err
	}
	defer termbox.Close()

	var password []byte

	// Función para actualizar la pantalla
	update := func() {
		termbox.Clear(termbox.ColorDefault, termbox.ColorDefault)

		prompt := "Contrasenya:"
		mask := strings.Repeat("*", len(password))
		strength := PasswordStrength(string(password))

		// Muestra la línea de contraseña
		drawString(0, 0, prompt+mask, termbox.ColorWhite, termbox.ColorDefault)

		// Muestra la fortaleza
		strengthColor := termbox.ColorRed
		if strength == "Media" {
			strengthColor = termbox.ColorYellow
		} else if strength == "Fuerte" {
			strengthColor = termbox.ColorGreen
		} else if strength == "Muy fuerte" {
			strengthColor = termbox.ColorCyan
		}

		drawString(0, 1, "Fortaleza: "+strength, strengthColor, termbox.ColorDefault)

		// Instrucciones
		drawString(0, 3, "Presione ENTER para confirmar", termbox.ColorWhite, termbox.ColorDefault)

		termbox.Flush()
	}

	// Dibuja el estado inicial
	update()

	// Bucle principal
	for {
		ev := termbox.PollEvent()
		if ev.Type == termbox.EventKey {
			switch {
			case ev.Key == termbox.KeyEsc:
				return "", fmt.Errorf("entrada cancelada")
			case ev.Key == termbox.KeyEnter:
				return string(password), nil
			case ev.Key == termbox.KeyBackspace || ev.Key == termbox.KeyBackspace2:
				if len(password) > 0 {
					password = password[:len(password)-1]
				}
			case ev.Key == termbox.KeySpace:
				password = append(password, ' ')
			case ev.Ch != 0:
				password = append(password, byte(ev.Ch))
			}

			update()
		} else if ev.Type == termbox.EventResize {
			// Aquí simplemente necesitamos actualizar la pantalla, no necesitamos usar
			// las nuevas dimensiones directamente
			update()
		}
	}
}

// Función auxiliar para dibujar texto
func drawString(x, y int, str string, fg, bg termbox.Attribute) {
	for i, c := range str {
		termbox.SetCell(x+i, y, c, fg, bg)
	}
}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
func (c *client) registerUser() {
	ui.ClearScreen()
	fmt.Println("** Registro de usuario **")

	// generamos un par de claves (privada, pública) para el servidor
	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // aceleramos su uso con un precálculo

	pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
	chk(err)

	keyPub := pkClient.Public()           // extraemos la clave pública por separado
	pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
	chk(err)

	username := ui.ReadInput("Nombre de usuario")

	// Generar y sugerir una contraseña segura
	suggestedPassword, err := GenerateComplexPassword(12)
	chk(err)
	fmt.Printf("Contraseña sugerida: %s (Fortaleza: %s)\n",
		suggestedPassword, PasswordStrength(suggestedPassword))
	fmt.Println("¿Desea usar esta contraseña? (s/n)")

	var response string
	fmt.Scanln(&response)

	var password string
	if strings.ToLower(response) == "s" {
		password = suggestedPassword
	} else {
		// Usar la nueva función interactiva
		password, err = ReadPasswordWithLiveStrength()
		chk(err)
	}

	// Eliminar esta línea que muestra la contraseña en texto claro
	// fmt.Print(password)

	apellido := ui.ReadInput("Apellido")
	especialidad := ui.ReadInput("ID de especialidad") //ID?
	hospital := ui.ReadInput("ID de hospital")

	keyClient := sha512.Sum512([]byte(password))
	keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
	keyData := keyClient[32:64] // la otra para los datos (256 bits)

	data := url.Values{}
	data.Set("cmd", "register")
	data.Set("username", username)
	data.Set("password", encode64([]byte(keyLogin)))
	data.Set("apellido", apellido)
	data.Set("especialidad", especialidad)
	data.Set("hospital", hospital)
	data.Set("pubkey", encode64(compress(pubJSON)))

	// comprimimos, ciframos y codificamos la clave privada
	data.Set("prikey", encode64(encrypt(compress(pkJSON), keyData)))

	r, err := c.httpCliente.PostForm("https://localhost:10443", data)
	chk(err)

	// Decodificar la respuesta JSON en lugar de solo imprimirla
	var resp api.Response
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&resp)
	chk(err)
	defer r.Body.Close()

	if resp.Success == 1 {
		fmt.Println("Registro exitoso.")
		if otpauth := resp.Data; otpauth != "" {
			fmt.Printf("Configura TOTP en Google Authenticator usando este URI:\n%s\n", otpauth)

			// Genera y muestra el código QR en la terminal
			qrterminal.Generate(otpauth, qrterminal.L, os.Stdout)

			fmt.Println("O introduce manualmente el secreto en la app (copiar desde el URI).")
		} else {
			fmt.Println("Error: No se recibió un secreto TOTP válido")
		}
	} else {
		fmt.Printf("Error: %s\n", resp.Message)
	}
}

// loginUser pide credenciales y realiza un login en el servidor.
func (c *client) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Inicio de sesión **")

	username := ui.ReadInput("Nombre de usuario:")
	fmt.Print("Contraseña: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	chk(err)
	fmt.Println() // Añadimos un salto de línea después de introducir la contraseña
	password := string(passwordBytes)

	keyClient := sha512.Sum512([]byte(password))
	keyLogin := keyClient[:32] // una mitad para el login (256 bits)

	// generamos un par de claves (privada, pública) para el servidor
	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // aceleramos su uso con un precálculo

	data := url.Values{}
	data.Set("cmd", "login")                 // comando (string)
	data.Set("username", username)           // usuario (string)
	data.Set("password", encode64(keyLogin)) // contraseña (a base64 porque es []byte)
	r, err := c.httpCliente.PostForm("https://localhost:10443", data)
	chk(err)
	body, err := io.ReadAll(r.Body)
	chk(err)

	err = json.Unmarshal(body, &resp)
	chk(err)

	if resp.Success == 1 {

		fmt.Println(resp.Message)
		code := ui.ReadInput("Introduce tu código TOTP")
		data := url.Values{}
		data.Set("cmd", "verifyTOTP")
		data.Set("username", username)
		data.Set("code", code)

		r, err := c.httpCliente.PostForm("https://localhost:10443", data)
		chk(err)
		body, err := io.ReadAll(r.Body)
		chk(err)

		err = json.Unmarshal(body, &resp)
		chk(err)

		if resp.Success != -1 {
			c.currentUser = username
			c.authToken = resp.Token
			c.TokenOTP = resp.TokenOTP
			fmt.Println("Message: ", resp.Message)
			return
		}

	}
	if resp.Success == -1 {
		fmt.Println(resp.Message)
	}

}

func (c *client) verHistorialPaciente() {
	ui.ClearScreen()
	fmt.Println("** Ver historial del paciente **")

	dni := ui.ReadInput("DNI del paciente: ")

	data := url.Values{}
	data.Set("cmd", "verHistorialPaciente")
	data.Set("token", c.authToken)
	data.Set("username", c.currentUser)
	data.Set("dni", dni)
	r, err := c.httpCliente.PostForm("https://localhost:10443", data)
	chk(err)
	body, err := io.ReadAll(r.Body)
	chk(err)

	err = json.Unmarshal(body, &resp)
	chk(err)

	if resp.Success == 0 {
		c.logoutUser()
		return
	}

	if resp.Success == -1 {
		fmt.Println("Mensaje:", resp.Message)
		if ui.Confirm("¿Desea dar de alta al paciente? (s/n)") {
			c.darAltaPaciente()
		}
		return
	}
	c.currentDNI = dni // Guardamos el DNI actual

	c.menuExpedientes(dni)
}
func (c *client) menuExpedientes(dni string) {
	for {
		ui.ClearScreen()
		fmt.Printf("Historial del paciente con DNI %s\n", dni)
		data := url.Values{}
		data.Set("cmd", "verHistorialPaciente")
		data.Set("token", c.authToken)
		data.Set("username", c.currentUser)
		data.Set("dni", dni)
		r, err := c.httpCliente.PostForm("https://localhost:10443", data)
		chk(err)
		body, err := io.ReadAll(r.Body)
		chk(err)

		err = json.Unmarshal(body, &resp)
		chk(err)

		if resp.Success == 0 {
			c.logoutUser()
			return
		}

		if resp.Success != 1 {
			fmt.Println("Error al obtener expedientes:", resp.Message)
			break
		}
		// Mostrar opciones
		options := []string{
			"Crear nuevo expediente",
			"Ver expedientes existentes",
			"Volver",
		}

		choice := ui.PrintMenu("Opciones", options)

		switch choice {
		case 1:
			c.crearExpediente()
		case 2:
			c.mostrarExpedientes(resp.Expedientes)
		case 3:
			return
		}
	}
}

func (c *client) crearExpediente() {
	ui.ClearScreen()
	fmt.Println("** Crear nuevo expediente **")

	observaciones := ui.ReadInput("Observaciones: ")
	tratamiento := ui.ReadInput("Tratamiento: ")
	data := url.Values{}
	data.Set("cmd", "crearExpediente")
	data.Set("token", c.authToken)
	data.Set("diagnostico", observaciones)
	data.Set("username", c.currentUser)
	data.Set("dni", c.currentDNI)
	data.Set("tratamiento", tratamiento)
	r, err := c.httpCliente.PostForm("https://localhost:10443", data)
	chk(err)
	body, err := io.ReadAll(r.Body)
	chk(err)

	err = json.Unmarshal(body, &resp)
	chk(err)

	if resp.Success == 0 {
		c.logoutUser()
		return
	}

	fmt.Println("Éxito:", resp.Success)
	fmt.Println("Mensaje:", resp.Message)
	ui.Pause("Pulsa [Enter] para continuar...")
}

func (c *client) darAltaPaciente() {
	ui.ClearScreen()
	fmt.Println("** Dar de alta al paciente **")

	nombre := ui.ReadInput("Nombre: ")
	apellido := ui.ReadInput("Apellido: ")
	var fecha_nacimiento string
	for {
		fecha_nacimiento = ui.ReadInput("Fecha de nacimiento (AAAA-dd-mm): ")
		_, err := time.Parse("2006-01-02", fecha_nacimiento) // Formato AAAA-DD-MM
		if err == nil {
			break
		}
		fmt.Println("Formato inválido. Usa AAAA-DD-MM (ejemplo: 1990-03-15)")
	}
	var dni string
	for {
		dni = ui.ReadInput("DNI del paciente: ")
		if validarDNI(dni) {
			break
		}
		fmt.Println("DNI inválido. Debe tener 9 caracteres y terminar en una letra (ejemplo: 12345678A)")
	}
	var sexo string
	for {
		sexo = strings.ToUpper(ui.ReadInput("Sexo (H,M,O): "))

		if sexo == "H" || sexo == "M" || sexo == "O" {
			break
		}
		fmt.Println("Sexo inválido. Debe ser H, M o O")
	}

	data := url.Values{}
	data.Set("cmd", "addPaciente")
	data.Set("nom_Paciente", nombre)
	data.Set("apellido", apellido)
	data.Set("fecha", fecha_nacimiento)
	data.Set("dni", dni)
	data.Set("sexo", sexo)
	data.Set("username", c.currentUser)
	data.Set("token", c.authToken)
	r, err := c.httpCliente.PostForm("https://localhost:10443", data)
	chk(err)
	body, err := io.ReadAll(r.Body)
	chk(err)

	err = json.Unmarshal(body, &resp)
	chk(err)

	if resp.Success == 0 {
		c.logoutUser()
	}
	fmt.Println("Éxito:", resp.Success)
	fmt.Println("Mensaje:", resp.Message)
}

// logoutUser llama a la acción logout en el servidor, y si es exitosa,
// borra la sesión local (currentUser/authToken).
func (c *client) logoutUser() {
	ui.ClearScreen()
	fmt.Println("** Cerrar sesión **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado.")
		return
	}

	data := url.Values{}
	data.Set("cmd", "logout")
	data.Set("username", c.currentUser)
	data.Set("token", c.authToken)
	r, err := c.httpCliente.PostForm("https://localhost:10443", data)
	chk(err)
	body, err := io.ReadAll(r.Body)
	chk(err)

	err = json.Unmarshal(body, &resp)
	chk(err)

	fmt.Println("Éxito:", resp.Success)
	fmt.Println("Mensaje:", resp.Message)

	// Si fue exitoso, limpiamos la sesión local.
	if resp.Success == 1 {
		c.currentUser = ""
		c.authToken = ""
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func validarDNI(dni string) bool {
	// 1. Longitud exacta de 9 caracteres
	if len(dni) != 9 {
		return false
	}

	// 2. Primeros 8 caracteres son dígitos
	for _, c := range dni[:8] {
		if !unicode.IsDigit(c) {
			return false
		}
	}

	// 3. Último carácter es letra (mayúscula o minúscula)
	ultimo := rune(dni[8])
	return unicode.IsLetter(ultimo)
}

func (c *client) obtenerDNIPaciente() (string, error) {
	for {
		dni := ui.ReadInput("DNI del paciente: ")
		if validarDNI(dni) {
			return dni, nil
		}
		fmt.Println("DNI inválido. Debe tener 9 caracteres y terminar en una letra (ejemplo: 12345678A)")
	}
}

func (c *client) mostrarExpedientes(expedientes [][]byte) {
	for {
		ui.ClearScreen()
		fmt.Println("** Expedientes del paciente **")
		var exp api.Expediente

		uniqueExpedientes := make(map[string]bool)
		counter := 1
		lista_expedientes := make([]api.Expediente, 0)
		for _, expData := range expedientes {

			if err := json.Unmarshal(expData, &exp); err != nil {
				fmt.Printf("Error unmarshaling expediente: %v\n", err)
				continue
			} else {
				lista_expedientes = append(lista_expedientes, exp)
			}

			if _, exists := uniqueExpedientes[exp.ID]; exists {
				continue
			}
			uniqueExpedientes[exp.ID] = true

			if len(exp.Observaciones) > 0 {
				fmt.Printf("%d. [ID: %s] %s - %s (por %s)\n",
					counter,
					exp.ID,
					exp.Observaciones[0].Fecha_actualizacion,
					exp.Observaciones[0].Diagnostico,
					exp.Username)
				counter++
			}

		}

		fmt.Println("\n0. Volver")
		fmt.Print("\nIngrese el ID del expediente a gestionar: ")
		var input string
		fmt.Scanln(&input)

		// Opción para volver
		if input == "0" {
			return
		}

		// Buscar el expediente seleccionado
		var expedienteSeleccionado []byte

		for _, expData := range expedientes {

			if err := json.Unmarshal(expData, &exp); err != nil {
				fmt.Printf("Error unmarshaling expediente: %v\n", err)
				continue
			}
			if exp.ID == input {
				expedienteSeleccionado = expData
			}

		}

		if expedienteSeleccionado == nil {
			fmt.Printf("No se encontró un expediente con ID %s\n", input)
			ui.Pause("Pulsa [Enter] para continuar...")
			continue
		}

		// Gestionar el expediente seleccionado
		c.gestionarExpediente(expedienteSeleccionado)

	}

}

func (c *client) gestionarExpediente(expedienteData []byte) {
	var exp struct {
		ID             string              `json:"id"`
		Fecha_creacion string              `json:"fecha_creacion"`
		Observaciones  []api.Observaciones `json:"observaciones"`
		Medico         string              `json:"medico"`
	}

	if err := json.Unmarshal(expedienteData, &exp); err != nil {
		fmt.Println("Error al procesar expediente:", err)
		ui.Pause("Pulsa [Enter] para continuar...")
		return
	}

	for {
		ui.ClearScreen()
		fmt.Printf("=== Expediente ID: %s ===\n", exp.ID)
		fmt.Printf("Fecha creación: %s\n", exp.Fecha_creacion)
		fmt.Printf("Médico responsable: %s\n", exp.Medico)
		fmt.Println("\n=== Observaciones ===")

		for i, obs := range exp.Observaciones {
			fmt.Printf("%d. [%s] %s\n", i+1, obs.Fecha_actualizacion, truncate(obs.Diagnostico, 60))
		}

		fmt.Println("\n1. Ver observación detallada")
		fmt.Println("2. Añadir nueva observación")
		fmt.Println("0. Volver")

		opcion := ui.ReadInt("Seleccione una opción:")

		switch opcion {
		case 0:
			return
		case 1:
			if len(exp.Observaciones) == 0 {
				fmt.Println("No hay observaciones disponibles")
				ui.Pause("Pulsa [Enter] para continuar...")
				continue
			}

			numObs := ui.ReadInt("Ingrese el número de observación a ver:")
			if numObs < 1 || numObs > len(exp.Observaciones) {
				fmt.Println("Número de observación inválido")
				ui.Pause("Pulsa [Enter] para continuar...")
				continue
			}

			obs := exp.Observaciones[numObs-1]
			ui.ClearScreen()
			fmt.Printf("=== Observación %d ===\n", numObs)
			fmt.Printf("Fecha: %s\n", obs.Fecha_actualizacion)
			fmt.Printf("Médico: %s\n", obs.Medico)
			fmt.Printf("Diagnóstico:\n%s\n", obs.Diagnostico)
			fmt.Printf("Tratamiento:\n%s\n", obs.Tratamiento)
			ui.Pause("Pulsa [Enter] para continuar...")

		case 2:
			nuevaObs := ui.ReadInput("Ingrese la nueva observación:")
			nuevoTratamiento := ui.ReadInput("Ingrese el nuevo tratamiento:")
			data := url.Values{}
			data.Set("cmd", "modificarExpediente")
			data.Set("username", c.currentUser)
			data.Set("token", c.authToken)
			data.Set("diagnostico", nuevaObs)
			data.Set("dni", c.currentDNI)
			data.Set("fecha", time.Now().Format("2006-01-02"))
			data.Set("id", exp.ID)
			data.Set("tratamiento", nuevoTratamiento)
			r, err := c.httpCliente.PostForm("https://localhost:10443", data)
			chk(err)
			body, err := io.ReadAll(r.Body)
			chk(err)

			err = json.Unmarshal(body, &resp)
			chk(err)
			if resp.Success == 1 {
				fmt.Println("Observación añadida correctamente")
				// Actualizamos los datos locales
				var updatedExp struct {
					Observaciones []api.Observaciones `json:"observaciones"`
				}
				if err := json.Unmarshal(expedienteData, &updatedExp); err == nil {
					exp.Observaciones = updatedExp.Observaciones
				}
			} else {
				fmt.Println("Error:", resp.Message)
			}
			ui.Pause("Pulsa [Enter] para continuar...")
		}
	}
}

// Función auxiliar para truncar texto
func truncate(text string, length int) string {
	if len(text) <= length {
		return text
	}
	return text[:length-3] + "..."
}

// Función para eliminar todos los archivos de la carpeta de QR
func (c *client) cleanupQRFolder() {
	// Asegurarse de que la carpeta existe
	if _, err := os.Stat(QR_FOLDER); os.IsNotExist(err) {
		c.log.Printf("La carpeta %s no existe, no hay nada que limpiar", QR_FOLDER)
		return
	}

	// Abrir la carpeta
	folder, err := os.Open(QR_FOLDER)
	if err != nil {
		c.log.Printf("Error al abrir la carpeta %s: %v", QR_FOLDER, err)
		return
	}
	defer folder.Close()

	// Leer la lista de archivos
	files, err := folder.Readdirnames(-1)
	if err != nil {
		c.log.Printf("Error al leer el contenido de la carpeta %s: %v", QR_FOLDER, err)
		return
	}

	// Eliminar cada archivo
	for _, file := range files {
		filePath := filepath.Join(QR_FOLDER, file)

		// No eliminar directorios (solo por seguridad)
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			c.log.Printf("Error al verificar archivo %s: %v", filePath, err)
			continue
		}

		// Si es directorio, saltar
		if fileInfo.IsDir() {
			continue
		}

		// Eliminar el archivo
		err = os.Remove(filePath)
		if err != nil {
			c.log.Printf("Error al eliminar archivo %s: %v", filePath, err)
		} else {
			c.log.Printf("Archivo eliminado: %s", filePath)
		}
	}

	c.log.Printf("Limpieza de la carpeta %s completada", QR_FOLDER)
}
