package models

import (
	"database/sql/driver"
	"fmt"
)

// ComponentType represents component type enum
type ComponentType string

const (
	ComponentTypePentagi        ComponentType = "pentagi"
	ComponentTypeScraper        ComponentType = "scraper"
	ComponentTypeLangfuseWorker ComponentType = "langfuse-worker"
	ComponentTypeLangfuseWeb    ComponentType = "langfuse-web"
	ComponentTypeGrafana        ComponentType = "grafana"
	ComponentTypeOtelcol        ComponentType = "otelcol"
	ComponentTypeWorker         ComponentType = "worker"
	ComponentTypeInstaller      ComponentType = "installer"
	ComponentTypeEngine         ComponentType = "engine"
)

func (ct ComponentType) String() string {
	return string(ct)
}

func (ct *ComponentType) Scan(value any) error {
	if value == nil {
		*ct = ""
		return nil
	}
	if bv, err := driver.String.ConvertValue(value); err == nil {
		if v, ok := bv.(string); ok {
			*ct = ComponentType(v)
			return nil
		}
	}
	return fmt.Errorf("cannot scan %T into ComponentType", value)
}

func (ct ComponentType) Value() (driver.Value, error) {
	return string(ct), nil
}

func (ct ComponentType) Valid() error {
	switch ct {
	case ComponentTypePentagi, ComponentTypeScraper,
		ComponentTypeLangfuseWorker, ComponentTypeLangfuseWeb,
		ComponentTypeGrafana, ComponentTypeOtelcol,
		ComponentTypeWorker, ComponentTypeInstaller, ComponentTypeEngine:
		return nil
	default:
		return fmt.Errorf("invalid ComponentType: %s", ct)
	}
}

// ComponentStatus represents component status enum
type ComponentStatus string

const (
	ComponentStatusUnused    ComponentStatus = "unused"
	ComponentStatusConnected ComponentStatus = "connected"
	ComponentStatusInstalled ComponentStatus = "installed"
	ComponentStatusRunning   ComponentStatus = "running"
)

func (cs ComponentStatus) String() string {
	return string(cs)
}

func (cs *ComponentStatus) Scan(value any) error {
	if value == nil {
		*cs = ""
		return nil
	}
	if bv, err := driver.String.ConvertValue(value); err == nil {
		if v, ok := bv.(string); ok {
			*cs = ComponentStatus(v)
			return nil
		}
	}
	return fmt.Errorf("cannot scan %T into ComponentStatus", value)
}

func (cs ComponentStatus) Value() (driver.Value, error) {
	return string(cs), nil
}

func (cs ComponentStatus) Valid() error {
	switch cs {
	case ComponentStatusUnused, ComponentStatusConnected,
		ComponentStatusInstalled, ComponentStatusRunning:
		return nil
	default:
		return fmt.Errorf("invalid ComponentStatus: %s", cs)
	}
}

// ProductStack represents product stack enum
type ProductStack string

const (
	ProductStackPentagi       ProductStack = "pentagi"
	ProductStackLangfuse      ProductStack = "langfuse"
	ProductStackObservability ProductStack = "observability"
	ProductStackWorker        ProductStack = "worker"
	ProductStackInstaller     ProductStack = "installer"
	ProductStackEngine        ProductStack = "engine"
)

func (ps ProductStack) String() string {
	return string(ps)
}

func (ps *ProductStack) Scan(value any) error {
	if value == nil {
		*ps = ""
		return nil
	}
	if bv, err := driver.String.ConvertValue(value); err == nil {
		if v, ok := bv.(string); ok {
			*ps = ProductStack(v)
			return nil
		}
	}
	return fmt.Errorf("cannot scan %T into ProductStack", value)
}

func (ps ProductStack) Value() (driver.Value, error) {
	return string(ps), nil
}

func (ps ProductStack) Valid() error {
	switch ps {
	case ProductStackPentagi, ProductStackLangfuse, ProductStackObservability,
		ProductStackWorker, ProductStackInstaller, ProductStackEngine:
		return nil
	default:
		return fmt.Errorf("invalid ProductStack: %s", ps)
	}
}

// OSType represents operating system enum
type OSType string

const (
	OSTypeWindows OSType = "windows"
	OSTypeLinux   OSType = "linux"
	OSTypeDarwin  OSType = "darwin"
)

func (os OSType) String() string {
	return string(os)
}

func (os *OSType) Scan(value any) error {
	if value == nil {
		*os = ""
		return nil
	}
	if bv, err := driver.String.ConvertValue(value); err == nil {
		if v, ok := bv.(string); ok {
			*os = OSType(v)
			return nil
		}
	}
	return fmt.Errorf("cannot scan %T into OSType", value)
}

func (os OSType) Value() (driver.Value, error) {
	return string(os), nil
}

func (os OSType) Valid() error {
	switch os {
	case OSTypeWindows, OSTypeLinux, OSTypeDarwin:
		return nil
	default:
		return fmt.Errorf("invalid OSType: %s", os)
	}
}

// ArchType represents CPU architecture enum
type ArchType string

const (
	ArchTypeAMD64 ArchType = "amd64"
	ArchTypeARM64 ArchType = "arm64"
)

func (arch ArchType) String() string {
	return string(arch)
}

func (arch *ArchType) Scan(value any) error {
	if value == nil {
		*arch = ""
		return nil
	}
	if bv, err := driver.String.ConvertValue(value); err == nil {
		if v, ok := bv.(string); ok {
			*arch = ArchType(v)
			return nil
		}
	}
	return fmt.Errorf("cannot scan %T into ArchType", value)
}

func (arch ArchType) Value() (driver.Value, error) {
	return string(arch), nil
}

func (arch ArchType) Valid() error {
	switch arch {
	case ArchTypeAMD64, ArchTypeARM64:
		return nil
	default:
		return fmt.Errorf("invalid ArchType: %s", arch)
	}
}
