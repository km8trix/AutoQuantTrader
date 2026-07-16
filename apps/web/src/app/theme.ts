import { alpha, createTheme } from '@mui/material/styles'

const palette = {
  canvas: '#07111f',
  surface: '#0c1828',
  raised: '#122238',
  border: '#263a52',
  text: '#e7edf5',
  muted: '#93a5ba',
  cyan: '#53d5e8',
  green: '#5ed6a4',
  amber: '#ffbd5c',
  red: '#ff6b78',
}

export const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: palette.cyan,
    },
    success: {
      main: palette.green,
    },
    warning: {
      main: palette.amber,
    },
    error: {
      main: palette.red,
    },
    background: {
      default: palette.canvas,
      paper: palette.surface,
    },
    text: {
      primary: palette.text,
      secondary: palette.muted,
    },
    divider: palette.border,
  },
  typography: {
    fontFamily:
      'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    h1: {
      fontSize: '1.75rem',
      fontWeight: 700,
      letterSpacing: '-0.025em',
      lineHeight: 1.2,
    },
    h2: {
      fontSize: '1rem',
      fontWeight: 700,
      letterSpacing: '-0.01em',
    },
    h3: {
      fontSize: '0.875rem',
      fontWeight: 700,
    },
    subtitle2: {
      fontSize: '0.72rem',
      fontWeight: 700,
      letterSpacing: '0.08em',
      textTransform: 'uppercase',
    },
    body2: {
      lineHeight: 1.55,
    },
    button: {
      fontWeight: 700,
      textTransform: 'none',
    },
  },
  shape: {
    borderRadius: 10,
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        html: {
          minWidth: 1280,
          minHeight: 720,
          backgroundColor: palette.canvas,
        },
        body: {
          minWidth: 1280,
          minHeight: 720,
          margin: 0,
          backgroundColor: palette.canvas,
          backgroundImage: `radial-gradient(circle at 85% -20%, ${alpha(
            palette.cyan,
            0.1,
          )}, transparent 38%)`,
        },
        '#root': {
          minWidth: 1280,
          minHeight: 720,
        },
        '*': {
          boxSizing: 'border-box',
        },
        '*:focus-visible': {
          outline: `3px solid ${palette.cyan}`,
          outlineOffset: 2,
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          border: `1px solid ${palette.border}`,
          boxShadow: `0 14px 36px ${alpha('#000000', 0.2)}`,
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          fontWeight: 700,
        },
      },
    },
    MuiTooltip: {
      defaultProps: {
        arrow: true,
      },
    },
  },
})
