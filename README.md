# n8n-nodes-dragos

This is an n8n community node for the [Dragos](https://www.dragos.com/) OT/ICS cybersecurity platform.

Dragos is the industrial cybersecurity leader, protecting critical infrastructure from cyber threats. This node allows you to integrate Dragos with your n8n workflows.

[n8n](https://n8n.io/) is a [fair-code licensed](https://docs.n8n.io/reference/license/) workflow automation platform.

## Installation

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation/) in the n8n community nodes documentation.

## Operations

### Asset
- **Get Many**: Retrieve multiple assets
- **Search**: Search assets with filters
- **Get Stats**: Get asset statistics grouped by field
- **Update Attributes**: Update asset attributes
- **Add Software Package**: Add a software package to an asset

### Notification
- **Get Many**: Retrieve notifications with FIQL filtering
- **Get**: Get a specific notification by ID
- **Update**: Update notifications matching a filter
- **Get Stats**: Get notification statistics

### Vulnerability
- **Get Many**: Retrieve vulnerabilities with pagination
- **Get Stats**: Get vulnerability statistics
- **Set State**: Enable/disable vulnerabilities

### Vulnerability Detection
- **Get Many**: Retrieve vulnerability detections
- **Get Stats**: Get detection statistics
- **Update**: Update vulnerability detections
- **Set Disposition**: Set disposition of detections
- **Export**: Export detections as CSV

### Data Import Job
- **Get Many**: List data import jobs
- **Get**: Get a specific job
- **Create**: Create a new import job
- **Continue**: Continue a paused job
- **Stop**: Stop a running job
- **Delete**: Delete a job

### Zone
- **Get Many**: List zones
- **Get**: Get a specific zone
- **Create**: Create a new zone
- **Update**: Update a zone
- **Delete**: Delete a zone

## Credentials

To use this node, you need to configure the Dragos API credentials:

1. **Base URL**: The URL of your Dragos instance (e.g., `https://portal.dragos.com`)
2. **API Key ID**: Your Dragos API Key ID
3. **API Key Secret**: Your Dragos API Key Secret

You can generate API keys in the Dragos platform under Settings > API Keys.

## Compatibility

This node has been tested with:
- n8n version 1.20+
- Dragos Platform API v4 (Assets), v2 (Notifications), v1 (Vulnerabilities, Auth, Data Import)

## Resources

- [n8n community nodes documentation](https://docs.n8n.io/integrations/community-nodes/)
- [Dragos Platform](https://www.dragos.com/)
- [Dragos API Documentation](https://portal.dragos.com/api/docs)

## License

[MIT](LICENSE)
