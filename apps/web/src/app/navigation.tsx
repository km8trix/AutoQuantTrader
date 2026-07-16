import AssessmentRoundedIcon from '@mui/icons-material/AssessmentRounded'
import CandlestickChartRoundedIcon from '@mui/icons-material/CandlestickChartRounded'
import DashboardRoundedIcon from '@mui/icons-material/DashboardRounded'
import DatasetRoundedIcon from '@mui/icons-material/DatasetRounded'
import FactCheckRoundedIcon from '@mui/icons-material/FactCheckRounded'
import GppGoodRoundedIcon from '@mui/icons-material/GppGoodRounded'
import HistoryEduRoundedIcon from '@mui/icons-material/HistoryEduRounded'
import HubRoundedIcon from '@mui/icons-material/HubRounded'
import ManageSearchRoundedIcon from '@mui/icons-material/ManageSearchRounded'
import MonitorHeartRoundedIcon from '@mui/icons-material/MonitorHeartRounded'
import RocketLaunchRoundedIcon from '@mui/icons-material/RocketLaunchRounded'
import ScienceRoundedIcon from '@mui/icons-material/ScienceRounded'
import SettingsRoundedIcon from '@mui/icons-material/SettingsRounded'
import type { SvgIconComponent } from '@mui/icons-material'

export interface NavigationItem {
  label: string
  path: string
  icon: SvgIconComponent
  description: string
}

export interface NavigationGroup {
  label: string
  items: NavigationItem[]
}

export const navigationGroups: NavigationGroup[] = [
  {
    label: 'Workspace',
    items: [
      {
        label: 'Overview',
        path: '/overview',
        icon: DashboardRoundedIcon,
        description: 'Account and system overview',
      },
    ],
  },
  {
    label: 'Data',
    items: [
      {
        label: 'Datasets',
        path: '/data/datasets',
        icon: DatasetRoundedIcon,
        description: 'Dataset manifests and ingestion',
      },
      {
        label: 'Data quality',
        path: '/data/quality',
        icon: FactCheckRoundedIcon,
        description: 'Quality issues and quarantine',
      },
    ],
  },
  {
    label: 'Research',
    items: [
      {
        label: 'Strategies',
        path: '/research/strategies',
        icon: ScienceRoundedIcon,
        description: 'Immutable strategy versions',
      },
      {
        label: 'Experiments',
        path: '/research/experiments',
        icon: HubRoundedIcon,
        description: 'Experiment families and comparisons',
      },
      {
        label: 'Backtests',
        path: '/research/backtests',
        icon: AssessmentRoundedIcon,
        description: 'Backtest runs and reports',
      },
    ],
  },
  {
    label: 'Trading',
    items: [
      {
        label: 'Deployments',
        path: '/trading/deployments',
        icon: RocketLaunchRoundedIcon,
        description: 'Deployment lifecycle',
      },
      {
        label: 'Orders',
        path: '/trading/orders',
        icon: CandlestickChartRoundedIcon,
        description: 'Order and fill activity',
      },
      {
        label: 'Portfolio',
        path: '/trading/portfolio',
        icon: MonitorHeartRoundedIcon,
        description: 'Positions, cash, and ledger',
      },
    ],
  },
  {
    label: 'Control',
    items: [
      {
        label: 'Risk',
        path: '/risk',
        icon: GppGoodRoundedIcon,
        description: 'Risk limits and decisions',
      },
      {
        label: 'Reconciliation',
        path: '/operations/reconciliation',
        icon: ManageSearchRoundedIcon,
        description: 'Broker reconciliation',
      },
      {
        label: 'Audit log',
        path: '/operations/audit',
        icon: HistoryEduRoundedIcon,
        description: 'Immutable operator audit trail',
      },
    ],
  },
  {
    label: 'System',
    items: [
      {
        label: 'Settings',
        path: '/settings',
        icon: SettingsRoundedIcon,
        description: 'Environment and session settings',
      },
    ],
  },
]
