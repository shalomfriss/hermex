import {
  Children,
  isValidElement,
  type CSSProperties,
  type ReactElement,
  type ReactNode,
  type SelectHTMLAttributes,
} from "react";
import { cn } from "@/lib/utils";

interface SelectOptionProps {
  children: ReactNode;
  value: string;
}

interface AccessibleSelectProps
  extends Omit<SelectHTMLAttributes<HTMLSelectElement>, "children" | "onChange" | "value"> {
  children: ReactNode;
  onValueChange?: (value: string) => void;
  style?: CSSProperties;
  value?: string;
}

/** Native select used where a visible label must name the control directly. */
export function AccessibleSelect({
  children,
  className,
  onValueChange,
  value,
  ...props
}: AccessibleSelectProps) {
  const options: ReactElement<SelectOptionProps>[] = [];
  Children.forEach(children, (child) => {
    if (isValidElement<SelectOptionProps>(child)) options.push(child);
  });

  return (
    <select
      {...props}
      className={cn(
        "h-9 w-full cursor-pointer border border-midground/15 bg-background/40 px-3 py-1 font-courier text-sm text-midground transition-colors hover:border-midground/25 focus-visible:border-midground/30 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-midground/30 disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      value={value}
      onChange={(event) => onValueChange?.(event.target.value)}
    >
      {options.map((option) => (
        <option key={option.props.value} value={option.props.value}>
          {option.props.children}
        </option>
      ))}
    </select>
  );
}

export function AccessibleSelectOption(props: SelectOptionProps) {
  void props;
  return null;
}
