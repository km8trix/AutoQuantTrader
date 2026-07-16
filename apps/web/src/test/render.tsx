import { ThemeProvider } from '@mui/material'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import type { ReactElement } from 'react'

import { theme } from '../app/theme'

export function renderWithProviders(element: ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })

  return {
    queryClient,
    ...render(
      <ThemeProvider theme={theme}>
        <QueryClientProvider client={queryClient}>{element}</QueryClientProvider>
      </ThemeProvider>,
    ),
  }
}
