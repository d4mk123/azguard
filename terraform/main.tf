terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.12"
    }
  }
}

provider "azurerm" {
  features {}

  subscription_id = var.subscription_id
}

# ---------------------------------------------------------------------------
# Networking core
# ---------------------------------------------------------------------------

resource "azurerm_resource_group" "main" {
  name     = "${var.prefix}-rg"
  location = var.location
}

resource "azurerm_virtual_network" "main" {
  name                = "${var.prefix}-vnet"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "a" {
  name                 = "subnet-a"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "b" {
  name                 = "subnet-b"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]
}

# subnet-c deliberately left without an NSG -> triggers 7.11
resource "azurerm_subnet" "c" {
  name                 = "subnet-c"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.3.0/24"]
}

# ---------------------------------------------------------------------------
# NSG-A: open admin + web ports to the internet (mirrors violation-nsg.json)
# ---------------------------------------------------------------------------

resource "azurerm_network_security_group" "violation" {
  name                = "violation-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "RDP"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
    description                = "Allow RDP from internet"
  }

  security_rule {
    name                       = "SSH"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
    description                = "Allow SSH from internet"
  }

  security_rule {
    name                       = "HTTP"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
    description                = "Allow HTTP from internet"
  }

  security_rule {
    name                       = "HTTPS"
    priority                   = 130
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
    description                = "Allow HTTPS from internet"
  }
}

resource "azurerm_subnet_network_security_group_association" "violation" {
  subnet_id                 = azurerm_subnet.a.id
  network_security_group_id = azurerm_network_security_group.violation.id
}

# ---------------------------------------------------------------------------
# NSG-B: Any/Any allow + shadowed SSH/RDP pairs (mirrors any-any + shadowed)
# ---------------------------------------------------------------------------

resource "azurerm_network_security_group" "anyany" {
  name                = "any-any-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Allow-all-inbound rule mirrors any-any-rule.json
  security_rule {
    name                       = "AllowAllInternet"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
    description                = "Allow all traffic from internet"
  }

  # Shadowed pair: broader AllowSSHFromVNet at lower priority shadows
  # the more specific DenySSHFromSubnet (mirrors shadowed-rules.json)
  security_rule {
    name                       = "AllowSSHFromVNet"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.0.0.0/16"
    destination_address_prefix = "*"
    description                = "Allow SSH from VNet"
  }

  security_rule {
    name                       = "DenySSHFromSubnet"
    priority                   = 150
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.0.1.0/24"
    destination_address_prefix = "*"
    description                = "Deny SSH from subnet-a - shadowed by AllowSSHFromVNet"
  }

  security_rule {
    name                       = "AllowRDPFromVNet"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "10.0.0.0/16"
    destination_address_prefix = "*"
    description                = "Allow RDP from VNet"
  }

  security_rule {
    name                       = "DenyRDPFromSubnet"
    priority                   = 151
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "10.0.1.0/24"
    destination_address_prefix = "*"
    description                = "Deny RDP from subnet-a - shadowed by AllowRDPFromVNet"
  }
}

resource "azurerm_subnet_network_security_group_association" "anyany" {
  subnet_id                 = azurerm_subnet.b.id
  network_security_group_id = azurerm_network_security_group.anyany.id
}

# ---------------------------------------------------------------------------
# NSG-C: one statistically weird rule (mirrors one-weird-rule.json,
# exercises the Isolation Forest anomaly detector)
# ---------------------------------------------------------------------------

resource "azurerm_network_security_group" "weird" {
  name                = "weird-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "Weird-UDP-All"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
    description                = "Weird allow-all UDP rule for anomaly detection"
  }
}

# ---------------------------------------------------------------------------
# Network Watcher + VNet flow log (supports the 7.8 flow-log checks)
# ---------------------------------------------------------------------------

resource "azurerm_network_watcher" "main" {
  name                = "${var.prefix}-nw"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.prefix}-law"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
}

resource "azurerm_storage_account" "flowlogs" {
  name                     = "${replace(var.prefix, "-", "")}flogsa"
  location                 = azurerm_resource_group.main.location
  resource_group_name      = azurerm_resource_group.main.name
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_network_watcher_flow_log" "main" {
  network_watcher_name = azurerm_network_watcher.main.name
  resource_group_name  = azurerm_resource_group.main.name
  name                 = "${var.prefix}-vnet-flowlog"
  storage_account_id   = azurerm_storage_account.flowlogs.id
  enabled              = true

  retention_policy {
    enabled = true
    days    = 90
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.main.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.main.location
    workspace_resource_id = azurerm_log_analytics_workspace.main.id
    interval_in_minutes   = 10
  }

  target_resource_id = azurerm_virtual_network.main.id
}

# ---------------------------------------------------------------------------
# Flow-log retention is tested by the engine only if flow logs are surfaced;
# capture a second flow log with short retention to exercise the 7.5 failure.
# ---------------------------------------------------------------------------

resource "azurerm_network_security_group" "flowlog_nsg" {
  name                = "flowlog-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}
