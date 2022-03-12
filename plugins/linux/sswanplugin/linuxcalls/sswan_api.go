package linuxcalls

type sswanHandler interface {
  CreateConnection()
  DeleteConnection
}

func NewSswanHandler() *SswanHandler {
  return &sswanHandler{}
}
