	"bytes"
func ParsePatch(message []byte) (diff string) {
	s := bufio.NewScanner(bytes.NewReader(message))
	if err := s.Err(); err != nil {
		panic("error while scanning from memory: " + err.Error())