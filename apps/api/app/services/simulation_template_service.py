from __future__ import annotations

from datetime import datetime, timezone
from itertools import cycle
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.maturity import ControlMaturity
from app.db.models.simulation import Control, SimulationDefinition, SimulationRun, SimulationTemplate
from app.services.control_graph_service import ensure_canonical_controls, normalize_control_id, normalize_control_ids
from app.services.simulation_contract_service import validate_and_normalize_simulation_dsl


def _render_template(payload: Any, params: dict[str, Any]) -> Any:
    if isinstance(payload, str):
        rendered = payload
        for key, value in params.items():
            rendered = rendered.replace("{{" + key + "}}", str(value))
        return rendered
    if isinstance(payload, list):
        return [_render_template(item, params) for item in payload]
    if isinstance(payload, dict):
        return {key: _render_template(value, params) for key, value in payload.items()}
    return payload


def _validate_control_links(db: Session, *, tenant_id: str, control_ids: list[str]) -> list[str]:
    ensure_canonical_controls(db, tenant_id=tenant_id)
    normalized_ids = normalize_control_ids(control_ids)
    if not normalized_ids:
        raise ValueError("maps_to_controls must contain at least one control id")
    rows = db.scalars(
        select(Control).where(
            Control.id.in_(normalized_ids),
            Control.tenant_id == tenant_id,
        )
    ).all()
    found = {row.id for row in rows}
    missing = [control_id for control_id in normalized_ids if control_id not in found]
    if missing:
        raise ValueError(f"Unknown control ids in maps_to_controls: {', '.join(missing)}")
    return normalized_ids


def create_template(
    db: Session,
    *,
    tenant_id: str,
    name: str,
    description: str,
    status: str,
    category: str,
    target_module: str,
    version_prefix: str,
    parameter_schema: dict[str, Any],
    template_body: dict[str, Any],
    generation_defaults: dict[str, Any],
) -> SimulationTemplate:
    row = SimulationTemplate(
        tenant_id=tenant_id,
        name=name,
        description=description,
        status=status,
        category=category,
        target_module=target_module,
        version_prefix=version_prefix,
        parameter_schema=parameter_schema,
        template_body=template_body,
        generation_defaults=generation_defaults,
    )
    db.add(row)
    db.flush()
    return row


def generate_from_template(
    db: Session,
    *,
    tenant_id: str,
    template: SimulationTemplate,
    count: int,
    parameter_sets: list[dict[str, Any]] | None = None,
) -> list[SimulationDefinition]:
    if template.tenant_id != tenant_id:
        raise ValueError("Simulation template not found for tenant")

    if count <= 0:
        raise ValueError("count must be > 0")

    defaults = template.generation_defaults or {}
    source_params = parameter_sets if parameter_sets is not None else defaults.get("parameter_sets")
    source_params = source_params or [{}]

    generated: list[SimulationDefinition] = []
    params_iter = cycle(source_params)

    for index in range(count):
        params = dict(next(params_iter))
        params.setdefault("index", index + 1)
        params.setdefault("uuid", uuid4().hex[:8])
        params.setdefault("timestamp", datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
        params.setdefault("template_name", template.name)
        params.setdefault("tenant_id", tenant_id)
        params.setdefault("simulation_version", f"{template.version_prefix}.{index + 1}")

        rendered = _render_template(template.template_body, params)
        if not isinstance(rendered, dict):
            raise ValueError("template_body must render to an object")

        name = str(rendered.get("name") or f"{template.name} #{index + 1}")
        category = str(rendered.get("category") or template.category)
        target_module = str(rendered.get("target_module") or template.target_module)
        version = str(rendered.get("version") or params["simulation_version"])

        dsl_id = str(rendered.get("id") or f"sim-{template.id[:8]}-{index + 1}-{params['uuid']}")
        rendered["id"] = dsl_id
        rendered["tenant_id"] = tenant_id
        rendered["name"] = name
        rendered["category"] = category
        rendered["target_module"] = target_module
        rendered["version"] = version

        normalized = validate_and_normalize_simulation_dsl(
            dsl_json=rendered,
            tenant_id=tenant_id,
            simulation_id=dsl_id,
            name=name,
            category=category,
            target_module=target_module,
            version=version,
        )

        control_ids = _validate_control_links(
            db,
            tenant_id=tenant_id,
            control_ids=list(normalized.get("maps_to_controls") or []),
        )
        normalized["maps_to_controls"] = control_ids

        row = SimulationDefinition(
            tenant_id=tenant_id,
            name=name,
            category=category,
            target_module=target_module,
            version=version,
            dsl_json=normalized,
        )
        db.add(row)
        db.flush()
        generated.append(row)

    return generated


def get_control_coverage(
    db: Session,
    *,
    tenant_id: str,
    control_id: str,
    trend_points: int = 20,
) -> dict[str, Any]:
    resolved_control_id = normalize_control_id(control_id) or control_id
    control = db.scalar(
        select(Control).where(
            Control.id == resolved_control_id,
            Control.tenant_id == tenant_id,
        )
    )
    if not control:
        raise ValueError("Control not found for tenant")

    sim_defs = db.scalars(select(SimulationDefinition).where(SimulationDefinition.tenant_id == tenant_id)).all()
    mapped = [
        sim
        for sim in sim_defs
        if resolved_control_id in normalize_control_ids(list((sim.dsl_json or {}).get("maps_to_controls") or []))
    ]
    mapped_ids = [row.id for row in mapped]

    runs: list[SimulationRun] = []
    if mapped_ids:
        runs = db.scalars(
            select(SimulationRun)
            .where(
                SimulationRun.tenant_id == tenant_id,
                SimulationRun.simulation_id.in_(mapped_ids),
            )
            .order_by(SimulationRun.started_at.desc())
            .limit(max(1, trend_points))
        ).all()

    trend = []
    pass_count = 0
    for row in runs:
        results = row.results or {}
        pass_rate = float(results.get("pass_rate", 1.0 if results.get("result") == "pass" else 0.0))
        if results.get("result") == "pass":
            pass_count += 1
        trend.append(
            {
                "run_id": row.id,
                "simulation_id": row.simulation_id,
                "started_at": row.started_at,
                "result": results.get("result", "fail"),
                "pass_rate": pass_rate,
                "iterations": int(results.get("iterations", 1)),
            }
        )

    maturity_rows = db.scalars(
        select(ControlMaturity)
        .where(
            ControlMaturity.tenant_id == tenant_id,
            ControlMaturity.control_id == control_id,
        )
        .order_by(ControlMaturity.updated_at.desc())
    ).all()

    return {
        "control_id": control.id,
        "control_name": control.name,
        "framework_refs": control.mapped_framework_refs or [],
        "mapped_simulations": [
            {
                "simulation_id": row.id,
                "name": row.name,
                "category": row.category,
                "target_module": row.target_module,
                "version": row.version,
            }
            for row in sorted(mapped, key=lambda item: item.name)
        ],
        "coverage_summary": {
            "simulation_count": len(mapped),
            "run_count": len(runs),
            "overall_pass_rate": round((pass_count / len(runs)), 6) if runs else 0.0,
        },
        "pass_rate_trend": trend,
        "maturity_impact": [
            {
                "ai_system_id": row.ai_system_id,
                "technical_enforcement_score": row.technical_enforcement_score,
                "simulation_pass_rate": row.simulation_pass_rate,
                "coverage_score": row.coverage_score,
                "maturity_score": row.maturity_score,
                "status": row.status,
                "updated_at": row.updated_at,
            }
            for row in maturity_rows
        ],
    }


def get_framework_coverage(
    db: Session,
    *,
    tenant_id: str,
    framework_name: str,
    min_simulations: int,
) -> dict[str, Any]:
    if min_simulations <= 0:
        raise ValueError("min_simulations must be > 0")

    all_controls = db.scalars(
        select(Control).where(Control.tenant_id == tenant_id)
    ).all()

    framework_controls: list[Control] = []
    for control in all_controls:
        refs = control.mapped_framework_refs or []
        if any(str(ref.get("framework", "")).lower() == framework_name.lower() for ref in refs if isinstance(ref, dict)):
            framework_controls.append(control)

    sim_defs = db.scalars(select(SimulationDefinition).where(SimulationDefinition.tenant_id == tenant_id)).all()
    simulation_count_by_control: dict[str, int] = {}
    for sim in sim_defs:
        for control_id in normalize_control_ids(list((sim.dsl_json or {}).get("maps_to_controls") or [])):
            simulation_count_by_control[control_id] = simulation_count_by_control.get(control_id, 0) + 1

    covered_controls = [control for control in framework_controls if simulation_count_by_control.get(control.id, 0) >= min_simulations]
    total_controls = len(framework_controls)
    covered_total = len(covered_controls)
    coverage_percent = round((covered_total / total_controls) * 100.0, 4) if total_controls else 0.0

    return {
        "framework": framework_name,
        "tenant_id": tenant_id,
        "min_simulations": min_simulations,
        "coverage_percent": coverage_percent,
        "total_controls": total_controls,
        "covered_controls": covered_total,
        "controls": [
            {
                "control_id": control.id,
                "control_name": control.name,
                "simulation_count": simulation_count_by_control.get(control.id, 0),
                "covered": simulation_count_by_control.get(control.id, 0) >= min_simulations,
            }
            for control in sorted(framework_controls, key=lambda item: item.id)
        ],
    }
