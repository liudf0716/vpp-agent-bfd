package linuxcalls

type SswanAPI interface {
  Init()  error
  
  SswanAPIWrite
  SswanAPIRead
}

type SswanAPIWrite interface {
}

type SswanAPIRead interface {
}

func NewSswanHandler() *SswanHandler {
  return &SswanHandler{}
}
