package packet

import "fmt"

type DataTooShortError struct {
	Expected, Actual int
}

func (e *DataTooShortError) Error() string {
	return fmt.Sprintf("data too short, %d < %d", e.Actual, e.Expected)
}
