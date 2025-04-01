package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"prac/pkg/api"
	"prac/pkg/ui"
)

// client estructura interna no exportada que controla
// el estado de la sesión (usuario, token) y logger.
type client struct {
	log              *log.Logger
	currentUser      string
	authToken        api.Token
	currentSpecialty int //nuevo
	currentHospital  int //nuevo
	currentDNI       string
}

type Observaciones struct {
	Fecha_actualizacion string `json:"fecha_actualizacion"`
	Diagnostico         string `json:"diagnostico"`
	Medico              string `json:"medico"`
}

// Run es la única función exportada de este paquete.
// Crea un client interno y ejecuta el bucle principal.
func Run() {
	// Creamos un logger con prefijo 'cli' para identificar
	// los mensajes en la consola.
	c := &client{
		log: log.New(os.Stdout, "[cli] ", log.LstdFlags),
	}
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
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		}

		// Pausa para que el usuario vea resultados.
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
func (c *client) registerUser() {
	ui.ClearScreen()
	fmt.Println("** Registro de usuario **")

	username := ui.ReadInput("Nombre de usuario")
	password := ui.ReadInput("Contraseña")
	apellido := ui.ReadInput("Apellido")
	especialidad := ui.ReadInt("ID de especialidad") //ID?
	hospital := ui.ReadInt("ID de hospital")         //ID???

	// Enviamos la acción al servidor
	res := c.sendRequest(api.Request{
		Action:       api.ActionRegister,
		Username:     username,
		Password:     password,
		Apellido:     apellido,
		Especialidad: especialidad,
		Hospital:     hospital,
	})

	// Mostramos resultado
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

}

// loginUser pide credenciales y realiza un login en el servidor.
func (c *client) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Inicio de sesión **")

	username := ui.ReadInput("Nombre de usuario")
	password := ui.ReadInput("Contraseña")

	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: password,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si login fue exitoso, guardamos currentUser y el token.
	if res.Success == 1 {
		c.currentUser = username
		c.authToken = res.Token
		fmt.Println("Sesión iniciada con éxito. Token guardado.")
	}
}

func (c *client) verHistorialPaciente() {
	ui.ClearScreen()
	fmt.Println("** Ver historial del paciente **")

	dni := ui.ReadInput("DNI del paciente: ")
	res := c.sendRequest(api.Request{
		Action:   api.ActionObtenerExpedientes,
		Username: c.currentUser,
		Token:    c.authToken,
		DNI:      dni,
	})

	if res.Success == 0 {
		c.logoutUser()
		return
	}

	if res.Success == -1 {
		fmt.Println("Mensaje:", res.Message)
		if ui.Confirm("¿Desea dar de alta al paciente? (s/n)") {
			c.darAltaPaciente()
		}
		return
	}
	c.currentDNI = dni // Guardamos el DNI actual

	for {
		ui.ClearScreen()
		fmt.Printf("Historial del paciente con DNI %s\n", dni)
		options := []string{
			"Crear expediente",
			"Elegir expediente",
			"Salir",
		}
		choice := ui.PrintMenu("Opciones", options)

		switch choice {
		case 1: // Crear expediente
			c.crearExpediente()
		case 2: // Elegir expediente
			c.elegirExpediente(c.currentDNI)
		case 3: // Salir
			return
		}

	}
}

func (c *client) crearExpediente() {
	ui.ClearScreen()
	fmt.Println("** Crear nuevo expediente **")

	observaciones := ui.ReadInput("Observaciones: ")

	fmt.Println("DNI:", c.currentDNI)
	fmt.Println(c.authToken.Value)
	fmt.Println(c.currentUser)
	fmt.Println(observaciones)

	// Enviar solicitud al servidor
	res := c.sendRequest(api.Request{
		Action:      api.ActionCrearExpediente,
		Token:       c.authToken,
		Username:    c.currentUser,
		Diagnostico: observaciones,
		DNI:         c.currentDNI,
	})

	if res.Success == 0 {
		c.logoutUser()
		return
	}

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	ui.Pause("Pulsa [Enter] para continuar...")
}

func (c *client) elegirExpediente(dni string) {
	ui.ClearScreen()
	fmt.Println("** Elegir expediente **")

	// Obtener la lista de expedientes del servidor
	res := c.sendRequest(api.Request{
		Action: api.ActionObtenerExpedientes,
		Token:  c.authToken,
		DNI:    dni,
	})

	if res.Success == 0 {
		c.logoutUser()
		return
	}

	if res.Success == 1 {
		fmt.Println("Mensaje:", res.Message)
		return
	}

	// Parsear los expedientes
	type Expediente struct {
		Username      string          `json:"username"`
		Observaciones []Observaciones `json:"observaciones"`
		FechaCreacion string          `json:"fecha_creacion"`
		Especialidad  int             `json:"especialidad"`
	}

	var listaExpedientes []Expediente
	for _, expBytes := range res.Expedientes {
		var exp Expediente
		if err := json.Unmarshal(expBytes, &exp); err != nil {
			fmt.Println("Error al procesar expediente:", err)
			continue
		}
		listaExpedientes = append(listaExpedientes, exp)
	}

	if len(listaExpedientes) == 0 {
		fmt.Println("No se encontraron expedientes válidos")
		ui.Pause("Pulsa [Enter] para continuar...")

	} else {
		for {
			ui.ClearScreen()
			fmt.Printf("Expedientes de %s:\n", dni)
			options := make([]string, len(listaExpedientes))
			for i, exp := range listaExpedientes {
				options[i] = fmt.Sprintf("Fecha: %s - Observaciones: %s", exp.FechaCreacion, exp.Observaciones)
			}
			options = append(options, "Volver")

			choice := ui.PrintMenu("Seleccionar expediente", options)
			if choice == len(options) {
				return
			}

			selectedExp := listaExpedientes[choice-1]

			// Submenú para el expediente seleccionado
			ui.ClearScreen()
			fmt.Printf("Fecha: %s\n", selectedExp.FechaCreacion)
			subOptions := []string{"Visualizar", "Editar", "Volver"}
			subChoice := ui.PrintMenu("Opciones", subOptions)

			switch subChoice {
			case 1: // Visualizar
				fmt.Println("Observaciones:", selectedExp.Observaciones)
				fmt.Println("Creado por:", selectedExp.Username)
				fmt.Println("Fecha creación:", selectedExp.FechaCreacion)
				fmt.Println("Especialidad:", selectedExp.Especialidad)
				ui.Pause("Pulsa [Enter] para continuar...")
			case 2: // Editar
				observaciones := ui.ReadInput("Nueva observación: ")
				c.actualizarExpediente(choice-1, observaciones)
			case 3: // Volver
				continue
			}
		}

	}
}

// funcion Actualizar Expediente, se pasa como argumento el numero del expediente, el nombre, observaciones y token
func (c *client) actualizarExpediente(expID int, observaciones string) {
	ui.ClearScreen()
	fmt.Println("** Actualizar expediente **")

	// Obtener la fecha actual
	fechaActual := time.Now().Format("2006-01-02") // Formato YYYY-MM-DD, ajusta si necesitas otro

	// Enviar la solicitud al servidor
	res := c.sendRequest(api.Request{
		Action:      api.ActionModificarExpediente,
		Token:       c.authToken,
		ID:          expID,
		Username:    c.currentUser,
		Diagnostico: observaciones,
		Fecha:       fechaActual,
	})

	if res.Success == 0 {
		c.logoutUser()
	}

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

func (c *client) darAltaPaciente() {
	ui.ClearScreen()
	fmt.Println("** Dar de alta al paciente **")

	nombre := ui.ReadInput("Nombre: ")
	apellido := ui.ReadInput("Apellido: ")
	fecha_nacimiento := ui.ReadInput("Fecha de nacimiento (AAAA-dd-mm): ")
	dni := ui.ReadInput("DNI del paciente: ")
	sexo := ui.ReadInput("Sexo (H,M,O)")

	// Enviamos la acción al servidor
	res := c.sendRequest(api.Request{
		Action:   api.ActionDarAlta,
		Token:    c.authToken,
		Username: c.currentUser,
		Nombre:   nombre,
		Apellido: apellido,
		Fecha:    fecha_nacimiento,
		Sexo:     sexo,
		DNI:      dni,
		Hospital: c.currentHospital,
	})

	if res.Success == 0 {
		c.logoutUser()
	}

	// Mostramos resultado
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

// fetchData pide datos privados al servidor.
// El servidor devuelve la data asociada al usuario logueado.
func (c *client) fetchData() {
	ui.ClearScreen()
	fmt.Println("** Obtener datos del usuario **")

	// Chequeo básico de que haya sesión
	if c.currentUser == "" || c.authToken.Value == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Hacemos la request con ActionFetchData
	res := c.sendRequest(api.Request{
		Action:   api.ActionFetchData,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, mostramos la data recibida
	if res.Success == 1 {
		fmt.Println("Tus datos:", res.Data)
	}
}

// updateData pide nuevo texto y lo envía al servidor con ActionUpdateData.
func (c *client) updateData() {
	ui.ClearScreen()
	fmt.Println("** Actualizar datos del usuario **")

	if c.currentUser == "" || c.authToken.Value == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Leemos la nueva Data
	newData := ui.ReadInput("Introduce el contenido que desees almacenar")

	// Enviamos la solicitud de actualización
	res := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     newData,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}

// logoutUser llama a la acción logout en el servidor, y si es exitosa,
// borra la sesión local (currentUser/authToken).
func (c *client) logoutUser() {
	ui.ClearScreen()
	fmt.Println("** Cerrar sesión **")

	if c.currentUser == "" || c.authToken.Value == "" {
		fmt.Println("No estás logueado.")
		return
	}

	// Llamamos al servidor con la acción ActionLogout
	res := c.sendRequest(api.Request{
		Action:   api.ActionLogout,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, limpiamos la sesión local.
	if res.Success == 1 {
		c.currentUser = ""
		c.authToken = api.Token{}
	}
}

// sendRequest envía un POST JSON a la URL del servidor y
// devuelve la respuesta decodificada. Se usa para todas las acciones.
func (c *client) sendRequest(req api.Request) api.Response {
	jsonData, _ := json.Marshal(req)
	resp, err := http.Post("http://localhost:8080/api", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error al contactar con el servidor:", err)
		return api.Response{Success: -1, Message: "Error de conexión"}
	}
	defer resp.Body.Close()

	// Leemos el body de respuesta y lo desempaquetamos en un api.Response
	body, _ := io.ReadAll(resp.Body)
	var res api.Response
	_ = json.Unmarshal(body, &res)
	return res
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
