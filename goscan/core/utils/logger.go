package utils

import (
	"fmt"
	"github.com/fatih/color"
)

// ---------------------------------------------------------------------------------------
// LOGGER
// ---------------------------------------------------------------------------------------
type Logger struct{}

func InitLogger() *Logger {
	return &Logger{}
}

func (l *Logger) LogDebug(message string) {
	highlight := color.New(color.FgWhite).SprintFunc()
	reset := color.New(color.FgWhite).SprintFunc()
	fmt.Println(highlight("[-]"), reset(message))
}

func (l *Logger) LogInfo(message string) {
	highlight := color.New(color.FgBlue).SprintFunc()
	reset := color.New(color.FgWhite).SprintFunc()
	fmt.Println(highlight("[*]"), reset(message))
}

func (l *Logger) LogNotify(message string) {
	highlight := color.New(color.FgGreen).SprintFunc()
	fmt.Println(highlight("[+]"), highlight(message))
}

func (l *Logger) LogWarning(message string) {
	highlight := color.New(color.FgYellow).SprintFunc()
	fmt.Println(highlight("[?]"), highlight(message))
}

func (l *Logger) LogError(message string) {
	highlight := color.New(color.FgRed).SprintFunc()
	fmt.Println(highlight("[!]"), highlight(message))
}
