// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

import "time"

type Token struct {
	Value     string
	ExpiresAt time.Time
}

const (
	ActionRegister            = "register"
	ActionLogin               = "login"
	ActionFetchData           = "fetchData"
	ActionUpdateData          = "updateData"
	ActionLogout              = "logout"
	ActionDarAlta             = "darAlta"
	ActionObtenerExpedientes  = "obtenerExpedientes"
	ActionModificarExpediente = "modificarExpediente"
	ActionCrearExpediente     = "crearExpediente"
)

// Request y Response como antes
type Request struct { //omitempty es para que no aparezca en el json del request cuando se haga esta acción
	Action       string `json:"action"`
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`
	Token        Token  `json:"token,omitempty"` //es el valor del token
	Data         string `json:"data,omitempty"`
	Especialidad int    `json:"especialidad,omitempty"`
	Hospital     int    `json:"hospital,omitempty"`
	Apellido     string `json:"apellido,omitempty"`
	Sexo         string `json:"sexo,omitempty"`
	Nombre       string `json:"nombre,omitempty"`
	Fecha        string `json:"Fecha;omitempty"`
	//Medico        string `json:"medico;omitempty"`
	DNI         string `json:"dni;omitempty"`
	Diagnostico string `json:"diagnostico;omitempty"`
	ID          int    `json:"id;omitempty"`
}

type Response struct {
	Success     int      `json:"success"` //-1 false, 0 fallo de token y 1 true
	Message     string   `json:"message"`
	Token       Token    `json:"token,omitempty"`
	Data        string   `json:"data,omitempty"`
	Expedientes [][]byte `json:"expedientes,omitempty"` //lista con el id de los pacientes que tienen algún historial con su médico
	Hospital    int
}
