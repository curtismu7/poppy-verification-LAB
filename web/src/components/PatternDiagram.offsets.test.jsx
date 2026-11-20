import { describe, expect, it } from "vitest";
import { labelOverlaps, placeLabels } from "../diagram-kit/diagramKit.js";

// The old hand-rolled labelOffsets is gone: the kit places every label clear of the other labels and the boxes.
describe("label placement (the kit's)", () => {
  const box = (x, y) => ({ x, y, w: 200, h: 64 });
  const point = (b, side) => {
    if (side === "l") return [b.x, b.y + b.h / 2, "left"];
    if (side === "r") return [b.x + b.w, b.y + b.h / 2, "right"];
    if (side === "t") return [b.x + b.w / 2, b.y, "top"];
    return [b.x + b.w / 2, b.y + b.h, "bottom"];
  };
  it("six arrows between the same two boxes get six separate spots and no two labels overlap", () => {
    const edges = [0, 1, 2, 3, 4, 5].map((i) => ({ id: `e${i}`, text: `label ${i}`, from: point(box(0, 0), "r"), to: point(box(600, 0), "l"), prefer: 0 }));
    const placed = placeLabels({ edges, boxes: [box(0, 0), box(600, 0)] });
    expect(placed.size).toBe(6);
    expect(labelOverlaps(placed)).toBe(0);
  });
  it("a single label sits on its arrow's middle", () => {
    const edges = [{ id: "e0", text: "only", from: point(box(0, 0), "r"), to: point(box(600, 0), "l"), prefer: 0 }];
    const placed = placeLabels({ edges, boxes: [box(0, 0), box(600, 0)] });
    expect(placed.get("e0").y).toBeCloseTo(32, 0);
  });
});
