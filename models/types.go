package models

import (
	"database/sql/driver"
	"fmt"
)

// ComponentType represents component type enum
type ComponentType string

const (
	ComponentTypePentagi          ComponentType = "pentagi"
	ComponentTypeScraper          ComponentType = "scraper"
	ComponentTypeLangfuseWorker   ComponentType = "langfuse-worker"
	ComponentTypeLangfuseWeb      ComponentType = "langfuse-web"
	ComponentTypeGrafana          ComponentType = "grafana"
	ComponentTypeOtel             ComponentType = "otel"
	ComponentTypeWorker           ComponentType = "worker"
	ComponentTypeInstaller        ComponentType = "installer"
	ComponentTypeEngine           ComponentType = "engine"
	ComponentTypeMinio            ComponentType = "minio"
	ComponentTypeRedis            ComponentType = "redis"
	ComponentTypePostgres         ComponentType = "postgres"
	ComponentTypePgvector         ComponentType = "pgvector"
	ComponentTypeJaegerClickhouse ComponentType = "jaeger-clickhouse"
	ComponentTypeGraphiti         ComponentType = "graphiti"
	ComponentTypeNeo4j            ComponentType = "neo4j"
	ComponentTypeVictoriametrics  ComponentType = "victoriametrics"
	ComponentTypeClickhouse       ComponentType = "clickhouse"
	ComponentTypeLoki             ComponentType = "loki"
	ComponentTypeJaeger           ComponentType = "jaeger"
	ComponentTypeBrowseruse       ComponentType = "browseruse"
	ComponentTypeEngineRegistry   ComponentType = "engine-registry"
	ComponentTypeEngineScenario   ComponentType = "engine-scenario"
	ComponentTypePgexporter       ComponentType = "pgexporter"
	ComponentTypeNodeExporter     ComponentType = "node-exporter"
	ComponentTypeCadvisor         ComponentType = "cadvisor"
	ComponentTypeClickstore       ComponentType = "clickstore"
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

// AllComponentTypes is the component vocabulary, in one place.
//
// Everything that needs to know the whole set derives it from here: Valid(),
// the tests that guard the hand-written enum lists elsewhere, and anything that
// has to enumerate components. A component added to the constants above and
// forgotten here fails Valid() and is rejected on read, which is loud; the
// reverse — a constant listed here and nowhere else — cannot happen, because
// this list is written in terms of the constants.
//
// The order is the order of the PostgreSQL enum and the ClickHouse Enum8, so a
// reader comparing the three has a chance.
var AllComponentTypes = []ComponentType{
	ComponentTypePentagi,
	ComponentTypeScraper,
	ComponentTypeLangfuseWorker,
	ComponentTypeLangfuseWeb,
	ComponentTypeGrafana,
	ComponentTypeOtel,
	ComponentTypeWorker,
	ComponentTypeInstaller,
	ComponentTypeEngine,
	ComponentTypeMinio,
	ComponentTypeRedis,
	ComponentTypePostgres,
	ComponentTypePgvector,
	ComponentTypeJaegerClickhouse,
	ComponentTypeGraphiti,
	ComponentTypeNeo4j,
	ComponentTypeVictoriametrics,
	ComponentTypeClickhouse,
	ComponentTypeLoki,
	ComponentTypeJaeger,
	ComponentTypeBrowseruse,
	ComponentTypeEngineRegistry,
	ComponentTypeEngineScenario,
	ComponentTypePgexporter,
	ComponentTypeNodeExporter,
	ComponentTypeCadvisor,
	ComponentTypeClickstore,
}

var componentTypeSet = func() map[ComponentType]struct{} {
	set := make(map[ComponentType]struct{}, len(AllComponentTypes))
	for _, ct := range AllComponentTypes {
		set[ct] = struct{}{}
	}
	return set
}()

func (ct ComponentType) Valid() error {
	if _, ok := componentTypeSet[ct]; ok {
		return nil
	}
	return fmt.Errorf("invalid ComponentType: %s", ct)
}

// ComponentToStackMapping maps a component to the product stack it is versioned
// with. The update check answers per STACK, so a client that wants to correlate
// its own components with the answer needs this mapping. It is fixed: a
// component belongs to exactly one stack for the lifetime of the contract.
var ComponentToStackMapping = map[ComponentType]ProductStack{
	ComponentTypePentagi:          ProductStackPentagi,
	ComponentTypeScraper:          ProductStackPentagi,
	ComponentTypePgvector:         ProductStackPentagi,
	ComponentTypeLangfuseWorker:   ProductStackLangfuse,
	ComponentTypeLangfuseWeb:      ProductStackLangfuse,
	ComponentTypePostgres:         ProductStackLangfuse,
	ComponentTypeClickhouse:       ProductStackLangfuse,
	ComponentTypeRedis:            ProductStackLangfuse,
	ComponentTypeMinio:            ProductStackLangfuse,
	ComponentTypeGrafana:          ProductStackObservability,
	ComponentTypeOtel:             ProductStackObservability,
	ComponentTypeVictoriametrics:  ProductStackObservability,
	ComponentTypeLoki:             ProductStackObservability,
	ComponentTypeJaeger:           ProductStackObservability,
	ComponentTypeJaegerClickhouse: ProductStackObservability,
	ComponentTypeWorker:           ProductStackWorker,
	ComponentTypeInstaller:        ProductStackInstaller,
	ComponentTypeEngine:           ProductStackEngine,
	ComponentTypeEngineRegistry:   ProductStackEngine,
	ComponentTypeEngineScenario:   ProductStackEngine,
	ComponentTypeGraphiti:         ProductStackGraphiti,
	ComponentTypeNeo4j:            ProductStackGraphiti,
	ComponentTypeBrowseruse:       ProductStackBrowser,
	// The metrics exporters. Each belongs to the stack whose compose file starts
	// it, not to whatever it happens to observe: pgexporter sits in
	// docker-compose.yml beside the pgvector database it reports on, while
	// node-exporter and cadvisor come from docker-compose-observability.yml.
	ComponentTypePgexporter:   ProductStackPentagi,
	ComponentTypeNodeExporter: ProductStackObservability,
	ComponentTypeCadvisor:     ProductStackObservability,
	// The ClickHouse server behind Jaeger's trace storage. Shares an image with
	// the ClickHouse behind Langfuse and is a different component in a different
	// stack, which is the case the images identity key exists to express.
	ComponentTypeClickstore: ProductStackObservability,
}

// GetProductStack returns the product stack a component belongs to.
func (ct ComponentType) GetProductStack() ProductStack {
	if stack, ok := ComponentToStackMapping[ct]; ok {
		return stack
	}
	return ProductStackPentagi // default fallback
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
	ProductStackGraphiti      ProductStack = "graphiti"
	ProductStackBrowser       ProductStack = "browser"
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
		ProductStackWorker, ProductStackInstaller, ProductStackEngine,
		ProductStackGraphiti, ProductStackBrowser:
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
