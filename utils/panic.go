package utils

import (
	"log/slog"
	"runtime/debug"

	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	FileLogger  *lumberjack.Logger
	PanicLogger *slog.Logger
)

func PanicCrash() {
	if r := recover(); r != nil {
		PanicLogger.Error("panic detected",
			"panic", r,
			"stack", string(debug.Stack()),
		)
		FileLogger.Close()
		panic(r)
	}
}
