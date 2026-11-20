import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Background, BackgroundVariant, Controls, Handle, MarkerType, Position, ReactFlow, ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import DiagramStepBar from "./DiagramStepBar";
import { markEdges, useDiagramStepper } from "../hooks/useDiagramStepper";
import { REFIT_EVENT, useFitOnResize } from "../hooks/useFitOnResize";
import { ArrowNoLabel, EdgeLabels, FitOpen, Passport, PassportActions } from "../diagram-kit/DiagramKit.jsx";
import { boxPassport, sidePoint } from "../diagram-kit/diagramKit.js";
import "../diagram-kit/diagram-kit.css";
import "./PatternDiagram.css";

const FIT = { padding: 0.08 };
const HANDLES = [["t", Position.Top], ["b", Position.Bottom], ["l", Position.Left], ["r", Position.Right]];

function Box({ data }) {
  return (
    <div className={`pat-node pat-node--${data.kind}${data.on ? " pat-node--on" : ""}${data.passport ? " dk-open" : ""}`} data-testid={`pat-node-${data.id}`}>
      {HANDLES.map(([k, pos]) => (
        <span key={k}>
          <Handle id={`s-${k}`} type="source" position={pos} className="pat-handle" />
          <Handle id={`t-${k}`} type="target" position={pos} className="pat-handle" />
        </span>
      ))}
      {data.label}
      {data.passport && <Passport p={data.passport} />}
    </div>
  );
}
const nodeTypes = { box: Box };

// The arrow draws the curve only: every label is drawn by EdgeLabels, above the boxes, placed clear of the other labels and the boxes.
const edgeTypes = { arrow: ArrowNoLabel };

// Pick the sides of the two boxes that face each other, so an arrow leaves toward its target.
function sides(a, b) {
  const dx = b.x - a.x, dy = b.y - a.y;
  return Math.abs(dx) > Math.abs(dy) ? (dx > 0 ? ["r", "l"] : ["l", "r"]) : (dy > 0 ? ["b", "t"] : ["t", "b"]);
}

function Canvas({ pattern, graph, positions, onMove, stepper, open, setOpen, activeEdge = null }) {
  const ref = useRef(null);
  useFitOnResize(ref, FIT);
  const active = stepper && stepper.step >= 0 ? pattern.steps[stepper.step] : null;
  const nodes = pattern.nodes.map((n) => ({
    id: n.id, type: "box", position: positions[n.id], draggable: true, zIndex: n.id === open ? 10 : undefined, // an expanded box sits above its neighbours
    data: { id: n.id, label: n.label, kind: n.kind, on: !!active && (active.from === n.id || active.to === n.id), passport: n.id === open ? boxPassport(graph, n.id) : null },
  }));
  const pageDriven = activeEdge !== null && activeEdge >= 0;
  const edges = markEdges(pattern.steps.map((s, i) => {
    // Each arrow leaves the side facing its target; a reply uses the same pair of sides as its request (the kit separates the labels).
    const [a, b] = sides(positions[s.from], positions[s.to]);
    const cp = s.to === "rule";
    const now = stepper ? stepper.step === i : false;
    const seen = stepper && stepper.step >= 0 && i <= stepper.step;
    return {
      id: `e${i}`, source: s.from, target: s.to, sourceHandle: `s-${a}`, targetHandle: `t-${b}`, type: "arrow",
      animated: now,
      className: `pat-edge${cp ? " pat-edge--cp" : ""}${now ? " pat-edge--now" : ""}${stepper && stepper.step >= 0 && !seen ? " pat-edge--dim" : ""}`,
      markerEnd: { type: MarkerType.ArrowClosed },
    };
  }), pageDriven ? [activeEdge] : []);
  // One label per arrow, in a layer above the boxes, placed clear of the other labels and the boxes.
  const labels = pattern.steps.map((s, i) => ({
    id: `e${i}`, text: `${i + 1}. ${s.label}`, source: s.from, target: s.to, sourceHandle: edges[i].sourceHandle, targetHandle: edges[i].targetHandle,
    active: stepper ? stepper.step === i : false, dim: stepper && stepper.step >= 0 && !(i <= stepper.step),
  }));
  // What an expanded box can do: open the box at the far end of an arrow, close itself, and make a link that opens this page with the box expanded.
  const actions = useMemo(() => ({
    open: (id) => setOpen(id), close: () => setOpen(null),
    link: (id) => { const u = new URL(window.location.href); u.searchParams.set("box", id); return u.toString(); },
  }), [setOpen]);
  return (
    <div ref={ref} className="pat-canvas" data-testid="pattern-canvas">
      <PassportActions.Provider value={actions}>
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} fitView fitViewOptions={FIT} nodesConnectable={false} minZoom={0.3}
          onNodeClick={(_, n) => setOpen((o) => (o === n.id ? null : n.id))} onPaneClick={() => setOpen(null)}
          onNodeDragStop={(_, n) => onMove(n.id, n.position)} onNodeDrag={(_, n) => onMove(n.id, n.position)} proOptions={{ hideAttribution: true }}>
          <Background variant={BackgroundVariant.Dots} gap={18} />
          <Controls showInteractive={false} />
          <EdgeLabels items={labels} pointFor={(box, handle) => sidePoint(box, String(handle).split("-")[1])} fallback={{ w: 150, h: 56 }} />
          <FitOpen open={open} closePadding={FIT.padding} />
        </ReactFlow>
      </PassportActions.Provider>
    </div>
  );
}

// The explanation that travels with the walkthrough: beside the canvas, always the same size (no layout jump), so the arrow in focus
// and what it means are on screen together. Before Simulate it lists the steps; any step can be clicked to jump there.
function Narration({ steps, stepper }) {
  const i = stepper.step;
  const step = i >= 0 ? steps[i] : null;
  return (
    <aside className="pat-narr" aria-label="What each step means" data-testid="pattern-narration">
      {/* Live only while paused: during auto-play the step bar's short caption is the announcement, so a screen reader is not
          queued a full explanation every 2.5 s. Focusable, because on a narrow screen it scrolls. */}
      <div className="pat-narr__now" role="region" aria-label="Current step explanation" tabIndex={0} aria-live={stepper.paused ? "polite" : "off"} data-testid="pattern-now">
        {step ? (
          <>
            <p className="pat-narr__count">Step {i + 1} of {steps.length}</p>
            <h3>{step.label}</h3>
            <h4>What happens</h4>
            <p>{step.say}</p>
            {step.why && (<><h4>Why it matters</h4><p>{step.why}</p></>)}
          </>
        ) : (
          <>
            <h3>Press Simulate</h3>
            <p>The {steps.length} arrows play in order, and each one is explained here as it happens: what the request is, and why it is there. Pause any time, or pick a step below.</p>
          </>
        )}
      </div>
      <ol className="pat-narr__list">
        {steps.map((s, n) => (
          <li key={n}>
            <button type="button" className={`pat-narr__item${n === i ? " is-now" : n < i ? " is-done" : ""}`} aria-current={n === i ? "step" : undefined}
              onClick={() => stepper.goTo(n)} data-testid={`narr-step-${n}`}>
              <span className="pat-narr__n">{n + 1}</span> {s.label}
            </button>
          </li>
        ))}
      </ol>
    </aside>
  );
}

export default function PatternDiagram({ pattern, resetSignal = 0, activeEdge = null }) {
  const initial = useMemo(() => Object.fromEntries(pattern.nodes.map((n) => [n.id, { x: n.x, y: n.y }])), [pattern]);
  const [positions, setPositions] = useState(initial);
  const stepper = useDiagramStepper(pattern.steps.length);
  // The pattern as a graph (boxes and arrows) for the box details; a box's kind is its group.
  const graph = useMemo(() => ({ nodes: pattern.nodes.map((n) => ({ id: n.id, label: n.label, group: n.kind })), edges: pattern.steps.map((st, i) => ({ source: st.from, target: st.to, label: `${i + 1}. ${st.label}` })) }), [pattern]);
  const [open, setOpen] = useState(() => { const box = new URLSearchParams(window.location.search).get("box"); return box && pattern.nodes.some((n) => n.id === box) ? box : null; }); // a shared link's box
  const onMove = useCallback((id, p) => setPositions((cur) => ({ ...cur, [id]: { x: p.x, y: p.y } })), []);
  // A page that passes activeEdge at all (the chat, -1 before its first step) lights the arrow its own steps reached.
  // Pressing Simulate takes the canvas back until Stop, so the walkthrough always plays; the narration is on every page.
  const pageDriven = activeEdge !== null;
  const simulating = stepper.active || stepper.step >= 0;
  const pageHasArrow = pageDriven && activeEdge >= 0 && !simulating;
  const step = stepper.step >= 0 ? pattern.steps[stepper.step] : null;
  // Reset restores box positions as well as the walkthrough and the view. The page-level Reset raises resetSignal.
  const reset = useCallback(() => { stepper.stop(); setPositions(initial); setOpen(null); setTimeout(() => window.dispatchEvent(new Event(REFIT_EVENT)), 0); }, [stepper.stop, initial]); // eslint-disable-line react-hooks/exhaustive-deps
  const seen = useRef(resetSignal);
  useEffect(() => { if (seen.current !== resetSignal) { seen.current = resetSignal; reset(); } }, [resetSignal, reset]);
  return (
    <section className="pat" aria-label={pattern.title}>
      <h2 className="pat__title">{pattern.title}</h2>
      <p className="pat__lede">{pattern.intro}</p>
      <DiagramStepBar stepper={stepper} caption={step ? step.label : ""} testId="pattern-step-bar" />
      {pageHasArrow && activeEdge < pattern.steps.length && (
        <article className="track__now" data-testid="pattern-page-now">
          <h3>Arrow {activeEdge + 1}: {pattern.steps[activeEdge].label}</h3>
          <p>{pattern.steps[activeEdge].say}</p>
        </article>
      )}
      <button type="button" className="pat-reset" onClick={reset} data-testid="pattern-reset">Reset positions and walkthrough</button>
      <div className={`pat-stage${pageDriven ? " pat-stage--stacked" : ""}`}>
        <ReactFlowProvider>
          {/* The canvas follows the page's arrow while no walkthrough is playing. */}
          <Canvas pattern={pattern} graph={graph} positions={positions} onMove={onMove} stepper={pageHasArrow ? null : stepper} open={open} setOpen={setOpen} activeEdge={pageHasArrow ? activeEdge : null} />
        </ReactFlowProvider>
        <Narration steps={pattern.steps} stepper={stepper} />
      </div>
      <p className="keys">Drag any box. Moved: {Object.keys(positions).filter((k) => positions[k].x !== initial[k].x || positions[k].y !== initial[k].y).length} box(es).</p>
    </section>
  );
}
