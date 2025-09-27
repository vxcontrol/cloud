package sdk

import (
	"context"

	"github.com/sirupsen/logrus"
)

type Level string

const (
	LevelTrace Level = "trace"
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
	LevelFatal Level = "fatal"
	LevelPanic Level = "panic"
)

type Logger interface {
	SetLevel(level Level)
	GetLevel() Level
	Entry
}

type Entry interface {
	WithError(err error) Entry
	WithField(key string, value any) Entry
	WithFields(fields map[string]any) Entry
	WithContext(ctx context.Context) Entry
	Log
}

type Log interface {
	Trace(args ...any)
	Tracef(format string, args ...any)
	Debug(args ...any)
	Debugf(format string, args ...any)
	Info(args ...any)
	Infof(format string, args ...any)
	Warn(args ...any)
	Warnf(format string, args ...any)
	Error(args ...any)
	Errorf(format string, args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Panic(args ...any)
	Panicf(format string, args ...any)
}

type logger struct {
	*logrus.Logger
}

func (l *logger) SetLevel(level Level) {
	switch level {
	case LevelTrace, LevelDebug, LevelInfo, LevelWarn, LevelError, LevelFatal, LevelPanic:
		var lv logrus.Level
		if err := lv.UnmarshalText([]byte(level)); err != nil {
			l.Logger.SetLevel(logrus.InfoLevel)
		}
	}
}

func (l *logger) GetLevel() Level {
	return Level(l.Logger.GetLevel().String())
}

func (l *logger) WithError(err error) Entry {
	return &entry{Entry: l.Logger.WithError(err)}
}

func (l *logger) WithField(key string, value any) Entry {
	return &entry{Entry: l.Logger.WithField(key, value)}
}

func (l *logger) WithFields(fields map[string]any) Entry {
	return &entry{Entry: l.Logger.WithFields(fields)}
}

func (l *logger) WithContext(ctx context.Context) Entry {
	return &entry{Entry: l.Logger.WithContext(ctx)}
}

type entry struct {
	*logrus.Entry
}

func (e *entry) WithError(err error) Entry {
	return &entry{Entry: e.Entry.WithError(err)}
}

func (e *entry) WithField(key string, value any) Entry {
	return &entry{Entry: e.Entry.WithField(key, value)}
}

func (e *entry) WithFields(fields map[string]any) Entry {
	return &entry{Entry: e.Entry.WithFields(fields)}
}

func (e *entry) WithContext(ctx context.Context) Entry {
	return &entry{Entry: e.Entry.WithContext(ctx)}
}

func DefaultLogger() Logger {
	return &logger{Logger: logrus.StandardLogger()}
}

func WrapLogrus(l *logrus.Logger) Logger {
	return &logger{Logger: l}
}
