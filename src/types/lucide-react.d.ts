declare module 'lucide-react' {
  import { FC, SVGProps } from 'react'
  
  export interface IconProps extends SVGProps<SVGSVGElement> {
    size?: string | number
    color?: string
    strokeWidth?: string | number
  }
  
  export const Shield: FC<IconProps>
  export const Search: FC<IconProps>
  export const AlertTriangle: FC<IconProps>
  export const CheckCircle: FC<IconProps>
  export const Lock: FC<IconProps>
  export const Mail: FC<IconProps>
  export const ArrowLeft: FC<IconProps>
  export const Check: FC<IconProps>
  export const User: FC<IconProps>
} 