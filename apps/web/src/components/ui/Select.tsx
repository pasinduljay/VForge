"use client";

import {
  Children,
  Fragment,
  isValidElement,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactElement,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { Check, ChevronDown } from "lucide-react";
import { cn } from "@/lib/cn";

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface SelectProps {
  id?: string;
  name?: string;
  value?: string;
  defaultValue?: string;
  onChange?: (event: { target: { value: string; name?: string } }) => void;
  onValueChange?: (value: string) => void;
  options?: SelectOption[];
  children?: ReactNode;
  placeholder?: string;
  disabled?: boolean;
  required?: boolean;
  icon?: ReactNode;
  className?: string;
  menuClassName?: string;
  size?: "sm" | "md";
  "aria-label"?: string;
}

function extractNodeText(node: ReactNode): string {
  if (node === null || node === undefined || typeof node === "boolean") {
    return "";
  }
  if (typeof node === "string" || typeof node === "number") {
    return String(node);
  }
  if (Array.isArray(node)) {
    return node.map(extractNodeText).join("");
  }
  if (isValidElement<{ children?: ReactNode }>(node)) {
    return extractNodeText(node.props.children);
  }
  return "";
}

function parseOptionsFromChildren(children: ReactNode): SelectOption[] {
  const result: SelectOption[] = [];

  const visit = (nodes: ReactNode) => {
    Children.forEach(nodes, (child) => {
      if (!isValidElement(child)) {
        return;
      }
      if (child.type === Fragment) {
        const frag = child as ReactElement<{ children?: ReactNode }>;
        visit(frag.props.children);
        return;
      }
      if (child.type === "optgroup") {
        const grp = child as ReactElement<{ children?: ReactNode }>;
        visit(grp.props.children);
        return;
      }
      if (child.type === "option") {
        const opt = child as ReactElement<{
          value?: string | number;
          disabled?: boolean;
          children?: ReactNode;
        }>;
        const label = extractNodeText(opt.props.children).trim();
        const rawVal =
          opt.props.value !== undefined ? String(opt.props.value) : label;
        result.push({
          value: rawVal,
          label: label || rawVal,
          disabled: Boolean(opt.props.disabled),
        });
      }
    });
  };

  visit(children);
  return result;
}

export function Select({
  id,
  name,
  value,
  defaultValue,
  onChange,
  onValueChange,
  options,
  children,
  placeholder = "Select...",
  disabled = false,
  required = false,
  icon,
  className,
  menuClassName,
  size = "md",
  "aria-label": ariaLabel,
}: SelectProps) {
  const generatedId = useId();
  const listboxId = `${id ?? generatedId}-listbox`;
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);

  const resolvedOptions = useMemo<SelectOption[]>(() => {
    if (options && options.length > 0) {
      return options;
    }
    return parseOptionsFromChildren(children);
  }, [options, children]);

  const [internalValue, setInternalValue] = useState<string>(
    defaultValue ?? resolvedOptions[0]?.value ?? "",
  );
  const currentValue = value !== undefined ? value : internalValue;

  const selectedOption = useMemo(
    () => resolvedOptions.find((opt) => opt.value === currentValue),
    [resolvedOptions, currentValue],
  );

  const [open, setOpen] = useState(false);
  const [highlightedIndex, setHighlightedIndex] = useState(-1);
  const [menuStyle, setMenuStyle] = useState<{
    top: number;
    left: number;
    minWidth: number;
    maxWidth: number;
    placeAbove: boolean;
  } | null>(null);

  const computeMenuPosition = useCallback(() => {
    const trigger = triggerRef.current;
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const estimatedMenuHeight = Math.min(resolvedOptions.length * 36 + 14, 272);
    const spaceBelow = viewportHeight - rect.bottom - 12;
    const spaceAbove = rect.top - 12;
    const placeAbove =
      spaceBelow < estimatedMenuHeight && spaceAbove > spaceBelow;

    const minWidth = Math.max(rect.width, 196);
    const maxWidth = Math.max(220, viewportWidth - 24);
    const desiredWidth = Math.min(minWidth, maxWidth);
    const left = Math.max(
      12,
      Math.min(rect.left, viewportWidth - desiredWidth - 12),
    );
    const top = placeAbove ? Math.max(12, rect.top - 6) : rect.bottom + 6;

    setMenuStyle({
      top,
      left,
      minWidth: desiredWidth,
      maxWidth,
      placeAbove,
    });
  }, [resolvedOptions.length]);

  useEffect(() => {
    if (!open) return;
    computeMenuPosition();

    const handlePointerDown = (e: PointerEvent) => {
      const target = e.target as Node | null;
      if (!target) return;
      if (triggerRef.current?.contains(target)) return;
      if (menuRef.current?.contains(target)) return;
      setOpen(false);
    };

    const handleReposition = () => {
      computeMenuPosition();
    };

    const handleKeyGlobal = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };

    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyGlobal);
    window.addEventListener("resize", handleReposition);
    window.addEventListener("scroll", handleReposition, true);
    return () => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyGlobal);
      window.removeEventListener("resize", handleReposition);
      window.removeEventListener("scroll", handleReposition, true);
    };
  }, [open, computeMenuPosition]);

  const commitSelection = useCallback(
    (opt: SelectOption) => {
      if (opt.disabled) return;
      if (value === undefined) {
        setInternalValue(opt.value);
      }
      onValueChange?.(opt.value);
      onChange?.({ target: { value: opt.value, name } });
      setOpen(false);
      triggerRef.current?.focus();
    },
    [value, onValueChange, onChange, name],
  );

  const openMenu = () => {
    if (disabled) return;
    const currentIdx = resolvedOptions.findIndex(
      (opt) => opt.value === currentValue && !opt.disabled,
    );
    const firstEnabledIdx = resolvedOptions.findIndex((opt) => !opt.disabled);
    setHighlightedIndex(currentIdx >= 0 ? currentIdx : firstEnabledIdx);
    computeMenuPosition();
    setOpen(true);
  };

  const moveHighlight = (delta: 1 | -1) => {
    if (resolvedOptions.length === 0) return;
    let next = highlightedIndex;
    for (let i = 0; i < resolvedOptions.length; i++) {
      next = (next + delta + resolvedOptions.length) % resolvedOptions.length;
      if (!resolvedOptions[next]?.disabled) {
        setHighlightedIndex(next);
        return;
      }
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (disabled) return;
    if (!open) {
      if (
        e.key === "ArrowDown" ||
        e.key === "ArrowUp" ||
        e.key === "Enter" ||
        e.key === " "
      ) {
        e.preventDefault();
        openMenu();
      }
      return;
    }

    if (e.key === "ArrowDown") {
      e.preventDefault();
      moveHighlight(1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      moveHighlight(-1);
    } else if (e.key === "Home") {
      e.preventDefault();
      const first = resolvedOptions.findIndex((o) => !o.disabled);
      if (first >= 0) setHighlightedIndex(first);
    } else if (e.key === "End") {
      e.preventDefault();
      for (let i = resolvedOptions.length - 1; i >= 0; i--) {
        if (!resolvedOptions[i]?.disabled) {
          setHighlightedIndex(i);
          break;
        }
      }
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      const target = resolvedOptions[highlightedIndex];
      if (target && !target.disabled) {
        commitSelection(target);
      }
    } else if (e.key === "Tab") {
      setOpen(false);
    }
  };

  const displayLabel = selectedOption ? selectedOption.label : placeholder;
  const isPlaceholder =
    !selectedOption || (selectedOption.value === "" && !selectedOption.label);

  return (
    <div className="relative w-full">
      <button
        ref={triggerRef}
        id={id}
        type="button"
        role="combobox"
        aria-label={ariaLabel}
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-controls={open ? listboxId : undefined}
        disabled={disabled}
        onClick={() => (open ? setOpen(false) : openMenu())}
        onKeyDown={handleKeyDown}
        className={cn(
          "flex w-full items-center justify-between gap-2 rounded-lg border border-white/[0.09] bg-[#101013] text-left transition-colors focus:outline-none focus-visible:border-[#3872e8] focus-visible:ring-1 focus-visible:ring-[#3872e8]/45",
          size === "sm"
            ? "h-8 px-2.5 py-1 text-xs"
            : "min-h-[38px] px-3 py-2 text-[13px] leading-5",
          open
            ? "border-[#3872e8]/70 bg-[#141418]"
            : "hover:border-white/[0.16] hover:bg-[#141418]",
          disabled
            ? "cursor-not-allowed border-white/[0.06] bg-[#141418]/60 text-zinc-500 hover:border-white/[0.06] hover:bg-[#141418]/60"
            : isPlaceholder || selectedOption?.value === ""
              ? "text-zinc-400"
              : "text-[#f4f4f6]",
          className,
        )}
      >
        <span className="flex min-w-0 items-center gap-2">
          {icon ? <span className="shrink-0 text-zinc-400">{icon}</span> : null}
          <span className="truncate">{displayLabel}</span>
        </span>
        <ChevronDown
          className={cn(
            "h-3.5 w-3.5 shrink-0 text-zinc-400 transition-transform duration-150",
            open ? "rotate-180 text-zinc-200" : "",
          )}
        />
      </button>
      {required ? (
        <input
          type="text"
          tabIndex={-1}
          aria-hidden="true"
          required
          value={currentValue}
          onChange={() => {}}
          className="pointer-events-none absolute inset-x-0 bottom-0 h-px opacity-0"
        />
      ) : null}

      {open && menuStyle && typeof document !== "undefined"
        ? createPortal(
            <div
              ref={menuRef}
              id={listboxId}
              role="listbox"
              aria-label={ariaLabel}
              style={{
                position: "fixed",
                top: menuStyle.top,
                left: menuStyle.left,
                minWidth: menuStyle.minWidth,
                maxWidth: menuStyle.maxWidth,
                transform: menuStyle.placeAbove
                  ? "translateY(-100%)"
                  : undefined,
                zIndex: 70,
              }}
              className={cn(
                "rounded-xl border border-white/[0.09] bg-[#151519]/98 p-1 shadow-[0_18px_48px_rgba(0,0,0,0.75)] backdrop-blur-md",
                menuClassName,
              )}
            >
              <div className="max-h-64 space-y-0.5 overflow-y-auto py-0.5">
                {resolvedOptions.length === 0 ? (
                  <div className="px-3 py-2 text-xs text-zinc-500">
                    No options available
                  </div>
                ) : (
                  resolvedOptions.map((opt, idx) => {
                    const isSelected = opt.value === currentValue;
                    const isHighlighted = idx === highlightedIndex;
                    return (
                      <button
                        key={`${opt.value}-${idx}`}
                        type="button"
                        role="option"
                        aria-selected={isSelected}
                        disabled={opt.disabled}
                        onMouseEnter={() => {
                          if (!opt.disabled) setHighlightedIndex(idx);
                        }}
                        onClick={() => commitSelection(opt)}
                        className={cn(
                          "flex w-full items-center justify-between gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-[13px] transition-colors",
                          opt.disabled
                            ? "cursor-not-allowed text-zinc-600"
                            : isSelected
                              ? "bg-white/[0.09] font-medium text-white"
                              : isHighlighted
                                ? "bg-white/[0.06] text-zinc-100"
                                : opt.value === ""
                                  ? "text-zinc-400 hover:bg-white/[0.05] hover:text-zinc-200"
                                  : "text-zinc-300 hover:bg-white/[0.05] hover:text-white",
                        )}
                      >
                        <span className="truncate">{opt.label}</span>
                        {isSelected ? (
                          <Check className="h-3.5 w-3.5 shrink-0 text-[#5b8ef8]" />
                        ) : null}
                      </button>
                    );
                  })
                )}
              </div>
            </div>,
            document.body,
          )
        : null}
    </div>
  );
}
