"""
Application Dependency Injection Container for SAGEDRAL-ML.
Holds singleton references to all major subsystems (config, engines, modules)
so they can be accessed consistently from routers, background tasks, scripts,
and tests without tight global coupling or circular imports.

All components are Optional and default to None so the container can be used
in partial environments (e.g., API-only mode without capture thread).
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from sagedral_ml.config import Config
    from sagedral_ml.detection.signature_engine import SignatureEngine
    from sagedral_ml.detection.ml_engine import MLEngine
    from sagedral_ml.detection.decision_engine import DecisionEngine
    from sagedral_ml.ips.response import IPSModule
    from sagedral_ml.features.extractor import FlowAggregator
    from sagedral_ml.capture.sniffer import PacketCapture

logger = logging.getLogger("sagedral_ml.core.container")


@dataclass
class AppContainer:
    config: Optional["Config"] = None
    signature_engine: Optional[Any] = None
    ml_engine: Optional[Any] = None
    decision_engine: Optional[Any] = None
    ips_module: Optional[Any] = None
    aggregator: Optional[Any] = None
    capture_module: Optional[Any] = None

    def set_config(self, config: "Config") -> None:
        self.config = config
        logger.debug("AppContainer.config terpasang.")

    def set_signature_engine(self, engine: Any) -> None:
        self.signature_engine = engine
        logger.debug("AppContainer.signature_engine terpasang.")

    def set_ml_engine(self, engine: Any) -> None:
        self.ml_engine = engine
        logger.debug("AppContainer.ml_engine terpasang.")

    def set_decision_engine(self, engine: Any) -> None:
        self.decision_engine = engine
        logger.debug("AppContainer.decision_engine terpasang.")

    def set_ips_module(self, module: Any) -> None:
        self.ips_module = module
        logger.debug("AppContainer.ips_module terpasang.")

    def set_aggregator(self, aggregator: Any) -> None:
        self.aggregator = aggregator
        logger.debug("AppContainer.aggregator terpasang.")

    def set_capture_module(self, module: Any) -> None:
        self.capture_module = module
        logger.debug("AppContainer.capture_module terpasang.")

    def is_ready(self) -> bool:
        return (
            self.signature_engine is not None
            or self.ml_engine is not None
            or self.decision_engine is not None
        )

    def summary(self) -> dict:
        return {
            "config": self.config is not None,
            "signature_engine": self.signature_engine is not None,
            "ml_engine": self.ml_engine is not None,
            "decision_engine": self.decision_engine is not None,
            "ips_module": self.ips_module is not None,
            "aggregator": self.aggregator is not None,
            "capture_module": self.capture_module is not None,
        }


global_container: AppContainer = AppContainer()
