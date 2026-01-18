import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
	IDataObject,
	IHttpRequestMethods,
} from 'n8n-workflow';

async function makeRequest(
	context: IExecuteFunctions,
	method: IHttpRequestMethods,
	url: string,
	body?: IDataObject,
	qs?: IDataObject,
): Promise<IDataObject | IDataObject[]> {
	const options: IDataObject = {
		method,
		url,
		json: true,
	};

	if (body && Object.keys(body).length > 0) {
		options.body = body;
	}

	if (qs && Object.keys(qs).length > 0) {
		options.qs = qs;
	}

	return await context.helpers.requestWithAuthentication.call(context, 'dragosApi', options);
}

async function executeAssetOperation(
	context: IExecuteFunctions,
	itemIndex: number,
	operation: string,
	baseUrl: string,
): Promise<IDataObject | IDataObject[]> {
	if (operation === 'getMany' || operation === 'search') {
		const returnAll = context.getNodeParameter('returnAll', itemIndex) as boolean;
		const limit = returnAll ? 1000 : (context.getNodeParameter('limit', itemIndex) as number);
		const options = context.getNodeParameter('options', itemIndex, {}) as IDataObject;

		const body: IDataObject = {
			pagination: {
				pageNumber: 0,
				pageSize: limit,
			},
		};

		if (options.sortField) {
			body.pagination = {
				...(body.pagination as IDataObject),
				sorts: [{ field: options.sortField, descending: options.sortDescending || false }],
			};
		}

		const response = await makeRequest(context, 'POST', `${baseUrl}/api/v4/assets`, body);
		return (response as IDataObject).content as IDataObject[] || response;
	}

	if (operation === 'getStats') {
		const selector = context.getNodeParameter('selector', itemIndex, '{}') as string;
		const groupBys = context.getNodeParameter('groupBys', itemIndex, {}) as IDataObject;

		const body: IDataObject = {
			selector: JSON.parse(selector),
			groupBys: (groupBys.groupBy as IDataObject[])?.map((g) => ({
				field: g.field,
				interval: g.interval || undefined,
			})) || [],
		};

		return await makeRequest(context, 'POST', `${baseUrl}/api/v4/assets/stats`, body);
	}

	if (operation === 'updateAttributes') {
		const assetId = context.getNodeParameter('assetId', itemIndex) as number;
		const attributesParam = context.getNodeParameter('attributes', itemIndex, {}) as IDataObject;

		const attributes: IDataObject = {};
		if (attributesParam.attribute) {
			for (const attr of attributesParam.attribute as IDataObject[]) {
				attributes[attr.name as string] = attr.value;
			}
		}

		const body: IDataObject = {
			assetId,
			attributes,
		};

		return await makeRequest(context, 'POST', `${baseUrl}/api/v4/setAssetAttributes`, body);
	}

	if (operation === 'addSoftwarePackage') {
		const assetId = context.getNodeParameter('assetId', itemIndex) as number;
		const lookupType = context.getNodeParameter('packageLookupType', itemIndex) as string;

		let packageLookup: IDataObject;
		if (lookupType === 'id') {
			packageLookup = {
				type: 'id',
				id: context.getNodeParameter('packageId', itemIndex) as number,
			};
		} else {
			packageLookup = {
				type: 'coordinates',
				vendor: context.getNodeParameter('packageVendor', itemIndex) as string || null,
				name: context.getNodeParameter('packageName', itemIndex) as string,
				version: context.getNodeParameter('packageVersion', itemIndex) as string,
			};
		}

		const body: IDataObject = {
			assetId,
			packageLookup,
		};

		return await makeRequest(context, 'POST', `${baseUrl}/api/v4/addAssetSoftwarePackage`, body);
	}

	throw new NodeOperationError(context.getNode(), `Unknown operation: ${operation}`);
}

async function executeNotificationOperation(
	context: IExecuteFunctions,
	itemIndex: number,
	operation: string,
	baseUrl: string,
): Promise<IDataObject | IDataObject[]> {
	if (operation === 'getMany') {
		const returnAll = context.getNodeParameter('returnAll', itemIndex) as boolean;
		const limit = returnAll ? 1000 : (context.getNodeParameter('limit', itemIndex) as number);
		const filter = context.getNodeParameter('filter', itemIndex, '') as string;
		const options = context.getNodeParameter('options', itemIndex, {}) as IDataObject;

		const qs: IDataObject = {
			pageNumber: 1,
			pageSize: limit,
		};

		if (filter) {
			qs.filter = filter;
		}

		if (options.sortField) {
			qs.sortField = options.sortField;
			qs.sortDescending = options.sortDescending || false;
		}

		const response = await makeRequest(context, 'GET', `${baseUrl}/api/v2/notification`, undefined, qs);
		return (response as IDataObject).content as IDataObject[] || response;
	}

	if (operation === 'get') {
		const notificationId = context.getNodeParameter('notificationId', itemIndex) as number;

		const response = await makeRequest(
			context,
			'GET',
			`${baseUrl}/api/v2/notification/batch`,
			undefined,
			{ ids: [notificationId] },
		);
		const results = response as IDataObject[];
		return results.length > 0 ? results[0] : {};
	}

	if (operation === 'update') {
		const filter = context.getNodeParameter('filter', itemIndex, '') as string;
		const updateFields = context.getNodeParameter('updateFields', itemIndex, {}) as IDataObject;

		const qs: IDataObject = {};
		if (filter) {
			qs.filter = filter;
		}

		return await makeRequest(context, 'PUT', `${baseUrl}/api/v2/notification`, updateFields, qs);
	}

	if (operation === 'getStats') {
		const filter = context.getNodeParameter('filter', itemIndex, '') as string;

		const qs: IDataObject = {};
		if (filter) {
			qs.filter = filter;
		}

		return await makeRequest(context, 'GET', `${baseUrl}/api/v2/notification/stats`, undefined, qs);
	}

	throw new NodeOperationError(context.getNode(), `Unknown operation: ${operation}`);
}

async function executeVulnerabilityOperation(
	context: IExecuteFunctions,
	itemIndex: number,
	operation: string,
	baseUrl: string,
): Promise<IDataObject | IDataObject[]> {
	if (operation === 'getMany') {
		const selector = context.getNodeParameter('selector', itemIndex, '{}') as string;
		const returnAll = context.getNodeParameter('returnAll', itemIndex) as boolean;

		let pageNumber = 0;
		let pageSize = 10;

		if (!returnAll) {
			pageNumber = context.getNodeParameter('pageNumber', itemIndex, 0) as number;
			pageSize = context.getNodeParameter('pageSize', itemIndex, 10) as number;
		} else {
			pageSize = 1000;
		}

		const body: IDataObject = {
			selector: JSON.parse(selector),
			pagination: {
				pageNumber,
				pageSize,
			},
		};

		const response = await makeRequest(context, 'POST', `${baseUrl}/api/v1/vulnerability`, body);
		return (response as IDataObject).content as IDataObject[] || response;
	}

	if (operation === 'getStats') {
		const selector = context.getNodeParameter('selector', itemIndex, '{}') as string;
		const groupBys = context.getNodeParameter('groupBys', itemIndex, {}) as IDataObject;

		const body: IDataObject = {
			selector: JSON.parse(selector),
			groupBys: (groupBys.groupBy as IDataObject[])?.map((g) => ({
				field: g.field,
				interval: g.interval || undefined,
			})) || [],
		};

		return await makeRequest(context, 'POST', `${baseUrl}/api/v1/vulnerability/stats`, body);
	}

	if (operation === 'setState') {
		const selector = context.getNodeParameter('selector', itemIndex, '{}') as string;
		const parsedSelector = JSON.parse(selector);

		const body: IDataObject = {
			updates: parsedSelector.updates || [],
		};

		return await makeRequest(context, 'POST', `${baseUrl}/api/v1/vulnerability/setState`, body);
	}

	throw new NodeOperationError(context.getNode(), `Unknown operation: ${operation}`);
}

async function executeVulnerabilityDetectionOperation(
	context: IExecuteFunctions,
	itemIndex: number,
	operation: string,
	baseUrl: string,
): Promise<IDataObject | IDataObject[]> {
	if (operation === 'getMany') {
		const selector = context.getNodeParameter('selector', itemIndex, '{}') as string;
		const returnAll = context.getNodeParameter('returnAll', itemIndex) as boolean;

		let pageNumber = 0;
		let pageSize = 10;

		if (!returnAll) {
			pageNumber = context.getNodeParameter('pageNumber', itemIndex, 0) as number;
			pageSize = context.getNodeParameter('pageSize', itemIndex, 10) as number;
		} else {
			pageSize = 1000;
		}

		const body: IDataObject = {
			selector: JSON.parse(selector),
			pagination: {
				pageNumber,
				pageSize,
			},
		};

		const response = await makeRequest(context, 'POST', `${baseUrl}/api/v1/vulnerability/detection`, body);
		return (response as IDataObject).content as IDataObject[] || response;
	}

	if (operation === 'getStats') {
		const selector = context.getNodeParameter('selector', itemIndex, '{}') as string;
		const groupBys = context.getNodeParameter('groupBys', itemIndex, {}) as IDataObject;

		const body: IDataObject = {
			selector: JSON.parse(selector),
			groupBys: (groupBys.groupBy as IDataObject[])?.map((g) => ({
				field: g.field,
				interval: g.interval || undefined,
			})) || [],
		};

		return await makeRequest(context, 'POST', `${baseUrl}/api/v1/vulnerability/detection/stats`, body);
	}

	if (operation === 'update' || operation === 'setDisposition') {
		const detectionUpdates = context.getNodeParameter('detectionUpdates', itemIndex, {}) as IDataObject;

		const updates = (detectionUpdates.update as IDataObject[])?.map((u) => ({
			id: u.id,
			disposition: u.disposition,
			priority: u.priority,
			reason: u.reason,
		})) || [];

		const endpoint = operation === 'setDisposition'
			? '/api/v1/vulnerability/detection/setDisposition'
			: '/api/v1/vulnerability/detection/update';

		const body: IDataObject = { updates };

		return await makeRequest(context, 'POST', `${baseUrl}${endpoint}`, body);
	}

	if (operation === 'export') {
		const selector = context.getNodeParameter('selector', itemIndex, '{}') as string;

		const body: IDataObject = {
			selector: JSON.parse(selector),
			format: 'CSV',
			fieldMappings: [
				{ exportField: 'ID', vulnField: 'id' },
				{ exportField: 'CVE', vulnField: 'cve' },
				{ exportField: 'Severity', vulnField: 'severity' },
				{ exportField: 'Asset', vulnField: 'assetId' },
				{ exportField: 'Disposition', vulnField: 'disposition' },
			],
		};

		return await makeRequest(context, 'POST', `${baseUrl}/api/v1/vulnerability/detection/export`, body);
	}

	throw new NodeOperationError(context.getNode(), `Unknown operation: ${operation}`);
}

async function executeJobOperation(
	context: IExecuteFunctions,
	itemIndex: number,
	operation: string,
	baseUrl: string,
): Promise<IDataObject | IDataObject[]> {
	const ddisBaseUrl = `${baseUrl}/ddis`;

	if (operation === 'getMany') {
		const returnAll = context.getNodeParameter('returnAll', itemIndex) as boolean;
		const limit = returnAll ? 0 : (context.getNodeParameter('limit', itemIndex) as number);

		const qs: IDataObject = {
			page_size: limit,
			page_number: 0,
		};

		const response = await makeRequest(context, 'GET', `${ddisBaseUrl}/api/v1/jobs/`, undefined, qs);
		return (response as IDataObject).content as IDataObject[] || response;
	}

	if (operation === 'get') {
		const jobId = context.getNodeParameter('jobId', itemIndex) as string;
		return await makeRequest(context, 'GET', `${ddisBaseUrl}/api/v1/jobs/${jobId}`);
	}

	if (operation === 'create') {
		const jobType = context.getNodeParameter('jobType', itemIndex) as string;
		const parserId = context.getNodeParameter('parserId', itemIndex) as string;
		const networkId = context.getNodeParameter('networkId', itemIndex) as string;
		const confidence = context.getNodeParameter('confidence', itemIndex) as number;
		const additionalFields = context.getNodeParameter('jobAdditionalFields', itemIndex, {}) as IDataObject;

		const body: IDataObject = {
			job_type: jobType,
			parser_id: parserId,
			network_id: networkId,
			confidence,
			...additionalFields,
		};

		return await makeRequest(context, 'POST', `${ddisBaseUrl}/api/v1/jobs/`, body);
	}

	if (operation === 'continue') {
		const jobId = context.getNodeParameter('jobId', itemIndex) as string;
		const stepId = context.getNodeParameter('stepId', itemIndex, 'PARSE') as string;

		return await makeRequest(
			context,
			'POST',
			`${ddisBaseUrl}/api/v1/jobs/${jobId}/continue`,
			undefined,
			{ step_id: stepId },
		);
	}

	if (operation === 'stop') {
		const jobId = context.getNodeParameter('jobId', itemIndex) as string;
		return await makeRequest(context, 'POST', `${ddisBaseUrl}/api/v1/jobs/${jobId}/stop`);
	}

	if (operation === 'delete') {
		const jobId = context.getNodeParameter('jobId', itemIndex) as string;
		return await makeRequest(context, 'DELETE', `${ddisBaseUrl}/api/v1/jobs/${jobId}`);
	}

	throw new NodeOperationError(context.getNode(), `Unknown operation: ${operation}`);
}

async function executeZoneOperation(
	context: IExecuteFunctions,
	itemIndex: number,
	operation: string,
	baseUrl: string,
): Promise<IDataObject | IDataObject[]> {
	if (operation === 'getMany') {
		const returnAll = context.getNodeParameter('returnAll', itemIndex) as boolean;
		const limit = returnAll ? 1000 : (context.getNodeParameter('limit', itemIndex) as number);

		const body: IDataObject = {
			pagination: {
				pageNumber: 0,
				pageSize: limit,
			},
		};

		const response = await makeRequest(context, 'POST', `${baseUrl}/api/v4/zones`, body);
		return (response as IDataObject).content as IDataObject[] || response;
	}

	if (operation === 'get') {
		const zoneId = context.getNodeParameter('zoneId', itemIndex) as number;

		const body: IDataObject = {
			selector: {
				idIn: [zoneId.toString()],
			},
			pagination: {
				pageNumber: 0,
				pageSize: 1,
			},
		};

		const response = await makeRequest(context, 'POST', `${baseUrl}/api/v4/zones`, body);
		const content = (response as IDataObject).content as IDataObject[];
		return content && content.length > 0 ? content[0] : {};
	}

	if (operation === 'create') {
		const zoneName = context.getNodeParameter('zoneName', itemIndex) as string;
		const zoneFields = context.getNodeParameter('zoneFields', itemIndex, {}) as IDataObject;

		const body: IDataObject = {
			name: zoneName,
			...zoneFields,
		};

		return await makeRequest(context, 'POST', `${baseUrl}/api/v4/createZone`, body);
	}

	if (operation === 'update') {
		const zoneId = context.getNodeParameter('zoneId', itemIndex) as number;
		const zoneName = context.getNodeParameter('zoneName', itemIndex) as string;
		const zoneFields = context.getNodeParameter('zoneFields', itemIndex, {}) as IDataObject;

		const body: IDataObject = {
			id: zoneId,
			name: zoneName,
			...zoneFields,
		};

		return await makeRequest(context, 'POST', `${baseUrl}/api/v4/updateZone`, body);
	}

	if (operation === 'delete') {
		const zoneId = context.getNodeParameter('zoneId', itemIndex) as number;

		const body: IDataObject = {
			id: zoneId,
		};

		return await makeRequest(context, 'POST', `${baseUrl}/api/v4/deleteZone`, body);
	}

	throw new NodeOperationError(context.getNode(), `Unknown operation: ${operation}`);
}

export class Dragos implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Dragos',
		name: 'dragos',
		icon: 'file:dragos.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
		description: 'Interact with the Dragos OT/ICS cybersecurity platform',
		defaults: {
			name: 'Dragos',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				name: 'dragosApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Asset',
						value: 'asset',
					},
					{
						name: 'Notification',
						value: 'notification',
					},
					{
						name: 'Vulnerability',
						value: 'vulnerability',
					},
					{
						name: 'Vulnerability Detection',
						value: 'vulnerabilityDetection',
					},
					{
						name: 'Data Import Job',
						value: 'job',
					},
					{
						name: 'Zone',
						value: 'zone',
					},
				],
				default: 'asset',
			},

			// Asset Operations
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['asset'],
					},
				},
				options: [
					{
						name: 'Get Many',
						value: 'getMany',
						description: 'Get many assets',
						action: 'Get many assets',
					},
					{
						name: 'Search',
						value: 'search',
						description: 'Search assets with filters',
						action: 'Search assets',
					},
					{
						name: 'Get Stats',
						value: 'getStats',
						description: 'Get asset statistics',
						action: 'Get asset statistics',
					},
					{
						name: 'Update Attributes',
						value: 'updateAttributes',
						description: 'Update asset attributes',
						action: 'Update asset attributes',
					},
					{
						name: 'Add Software Package',
						value: 'addSoftwarePackage',
						description: 'Add software package to asset',
						action: 'Add software package to asset',
					},
				],
				default: 'getMany',
			},

			// Notification Operations
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['notification'],
					},
				},
				options: [
					{
						name: 'Get Many',
						value: 'getMany',
						description: 'Get many notifications',
						action: 'Get many notifications',
					},
					{
						name: 'Get',
						value: 'get',
						description: 'Get a notification by ID',
						action: 'Get a notification',
					},
					{
						name: 'Update',
						value: 'update',
						description: 'Update notifications',
						action: 'Update notifications',
					},
					{
						name: 'Get Stats',
						value: 'getStats',
						description: 'Get notification statistics',
						action: 'Get notification statistics',
					},
				],
				default: 'getMany',
			},

			// Vulnerability Operations
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['vulnerability'],
					},
				},
				options: [
					{
						name: 'Get Many',
						value: 'getMany',
						description: 'Get many vulnerabilities',
						action: 'Get many vulnerabilities',
					},
					{
						name: 'Get Stats',
						value: 'getStats',
						description: 'Get vulnerability statistics',
						action: 'Get vulnerability statistics',
					},
					{
						name: 'Set State',
						value: 'setState',
						description: 'Set enabled/disabled state of vulnerabilities',
						action: 'Set vulnerability state',
					},
				],
				default: 'getMany',
			},

			// Vulnerability Detection Operations
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['vulnerabilityDetection'],
					},
				},
				options: [
					{
						name: 'Get Many',
						value: 'getMany',
						description: 'Get many vulnerability detections',
						action: 'Get many vulnerability detections',
					},
					{
						name: 'Get Stats',
						value: 'getStats',
						description: 'Get vulnerability detection statistics',
						action: 'Get vulnerability detection statistics',
					},
					{
						name: 'Update',
						value: 'update',
						description: 'Update vulnerability detections',
						action: 'Update vulnerability detections',
					},
					{
						name: 'Set Disposition',
						value: 'setDisposition',
						description: 'Set disposition of vulnerability detections',
						action: 'Set disposition of vulnerability detections',
					},
					{
						name: 'Export',
						value: 'export',
						description: 'Export vulnerability detections as CSV',
						action: 'Export vulnerability detections',
					},
				],
				default: 'getMany',
			},

			// Data Import Job Operations
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['job'],
					},
				},
				options: [
					{
						name: 'Get Many',
						value: 'getMany',
						description: 'Get many data import jobs',
						action: 'Get many data import jobs',
					},
					{
						name: 'Get',
						value: 'get',
						description: 'Get a data import job by ID',
						action: 'Get a data import job',
					},
					{
						name: 'Create',
						value: 'create',
						description: 'Create a new data import job',
						action: 'Create a data import job',
					},
					{
						name: 'Continue',
						value: 'continue',
						description: 'Continue a data import job',
						action: 'Continue a data import job',
					},
					{
						name: 'Stop',
						value: 'stop',
						description: 'Stop a running data import job',
						action: 'Stop a data import job',
					},
					{
						name: 'Delete',
						value: 'delete',
						description: 'Delete a data import job',
						action: 'Delete a data import job',
					},
				],
				default: 'getMany',
			},

			// Zone Operations
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['zone'],
					},
				},
				options: [
					{
						name: 'Get Many',
						value: 'getMany',
						description: 'Get many zones',
						action: 'Get many zones',
					},
					{
						name: 'Get',
						value: 'get',
						description: 'Get a zone by ID',
						action: 'Get a zone',
					},
					{
						name: 'Create',
						value: 'create',
						description: 'Create a new zone',
						action: 'Create a zone',
					},
					{
						name: 'Update',
						value: 'update',
						description: 'Update a zone',
						action: 'Update a zone',
					},
					{
						name: 'Delete',
						value: 'delete',
						description: 'Delete a zone',
						action: 'Delete a zone',
					},
				],
				default: 'getMany',
			},

			// ========== Common Parameters ==========

			// Return All (for paginated endpoints)
			{
				displayName: 'Return All',
				name: 'returnAll',
				type: 'boolean',
				displayOptions: {
					show: {
						operation: ['getMany', 'search'],
					},
				},
				default: false,
				description: 'Whether to return all results or only up to a given limit',
			},
			{
				displayName: 'Limit',
				name: 'limit',
				type: 'number',
				displayOptions: {
					show: {
						operation: ['getMany', 'search'],
						returnAll: [false],
					},
				},
				typeOptions: {
					minValue: 1,
					maxValue: 1000,
				},
				default: 50,
				description: 'Max number of results to return',
			},

			// ========== Asset Parameters ==========

			// Asset ID for update
			{
				displayName: 'Asset ID',
				name: 'assetId',
				type: 'number',
				displayOptions: {
					show: {
						resource: ['asset'],
						operation: ['updateAttributes', 'addSoftwarePackage'],
					},
				},
				default: 0,
				required: true,
				description: 'The ID of the asset',
			},

			// Asset Attributes
			{
				displayName: 'Attributes',
				name: 'attributes',
				type: 'fixedCollection',
				typeOptions: {
					multipleValues: true,
				},
				displayOptions: {
					show: {
						resource: ['asset'],
						operation: ['updateAttributes'],
					},
				},
				default: {},
				options: [
					{
						name: 'attribute',
						displayName: 'Attribute',
						values: [
							{
								displayName: 'Name',
								name: 'name',
								type: 'string',
								default: '',
								description: 'Name of the attribute',
							},
							{
								displayName: 'Value',
								name: 'value',
								type: 'string',
								default: '',
								description: 'Value of the attribute',
							},
						],
					},
				],
			},

			// Software Package parameters
			{
				displayName: 'Package Lookup Type',
				name: 'packageLookupType',
				type: 'options',
				displayOptions: {
					show: {
						resource: ['asset'],
						operation: ['addSoftwarePackage'],
					},
				},
				options: [
					{
						name: 'By ID',
						value: 'id',
					},
					{
						name: 'By Coordinates',
						value: 'coordinates',
					},
				],
				default: 'id',
			},
			{
				displayName: 'Package ID',
				name: 'packageId',
				type: 'number',
				displayOptions: {
					show: {
						resource: ['asset'],
						operation: ['addSoftwarePackage'],
						packageLookupType: ['id'],
					},
				},
				default: 0,
				required: true,
				description: 'The ID of the software package',
			},
			{
				displayName: 'Package Vendor',
				name: 'packageVendor',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['asset'],
						operation: ['addSoftwarePackage'],
						packageLookupType: ['coordinates'],
					},
				},
				default: '',
				description: 'The vendor of the software package',
			},
			{
				displayName: 'Package Name',
				name: 'packageName',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['asset'],
						operation: ['addSoftwarePackage'],
						packageLookupType: ['coordinates'],
					},
				},
				default: '',
				required: true,
				description: 'The name of the software package',
			},
			{
				displayName: 'Package Version',
				name: 'packageVersion',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['asset'],
						operation: ['addSoftwarePackage'],
						packageLookupType: ['coordinates'],
					},
				},
				default: '',
				required: true,
				description: 'The version of the software package',
			},

			// ========== Notification Parameters ==========

			{
				displayName: 'Notification ID',
				name: 'notificationId',
				type: 'number',
				displayOptions: {
					show: {
						resource: ['notification'],
						operation: ['get'],
					},
				},
				default: 0,
				required: true,
				description: 'The ID of the notification',
			},

			{
				displayName: 'Filter (FIQL)',
				name: 'filter',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['notification'],
						operation: ['getMany', 'update', 'getStats'],
					},
				},
				default: '',
				placeholder: 'severity=gt=3;reviewed==false',
				description: 'FIQL filter expression. Example: severity=gt=3;reviewed==false',
			},

			{
				displayName: 'Update Fields',
				name: 'updateFields',
				type: 'collection',
				placeholder: 'Add Field',
				displayOptions: {
					show: {
						resource: ['notification'],
						operation: ['update'],
					},
				},
				default: {},
				options: [
					{
						displayName: 'Reviewed',
						name: 'reviewed',
						type: 'boolean',
						default: false,
						description: 'Whether the notification has been reviewed',
					},
					{
						displayName: 'Retained',
						name: 'retained',
						type: 'boolean',
						default: false,
						description: 'Whether the notification is retained',
					},
					{
						displayName: 'State',
						name: 'state',
						type: 'string',
						default: '',
						description: 'The state of the notification',
					},
				],
			},

			// ========== Vulnerability Parameters ==========

			{
				displayName: 'Selector',
				name: 'selector',
				type: 'json',
				displayOptions: {
					show: {
						resource: ['vulnerability', 'vulnerabilityDetection'],
						operation: ['getMany', 'getStats', 'update', 'setDisposition', 'export', 'setState'],
					},
				},
				default: '{}',
				description: 'JSON selector for filtering. Example: {"valueMatches":{"type":"exact","field":"severity","exact":"HIGH"}}',
			},

			{
				displayName: 'Page Number',
				name: 'pageNumber',
				type: 'number',
				displayOptions: {
					show: {
						resource: ['vulnerability', 'vulnerabilityDetection'],
						operation: ['getMany'],
						returnAll: [false],
					},
				},
				default: 0,
				description: 'Page number (0-indexed)',
			},

			{
				displayName: 'Page Size',
				name: 'pageSize',
				type: 'number',
				displayOptions: {
					show: {
						resource: ['vulnerability', 'vulnerabilityDetection'],
						operation: ['getMany'],
						returnAll: [false],
					},
				},
				default: 10,
				description: 'Number of items per page',
			},

			// Vulnerability Detection Update
			{
				displayName: 'Updates',
				name: 'detectionUpdates',
				type: 'fixedCollection',
				typeOptions: {
					multipleValues: true,
				},
				displayOptions: {
					show: {
						resource: ['vulnerabilityDetection'],
						operation: ['update', 'setDisposition'],
					},
				},
				default: {},
				options: [
					{
						name: 'update',
						displayName: 'Update',
						values: [
							{
								displayName: 'Detection ID',
								name: 'id',
								type: 'string',
								default: '',
								required: true,
								description: 'The ID of the vulnerability detection',
							},
							{
								displayName: 'Disposition',
								name: 'disposition',
								type: 'options',
								options: [
									{ name: 'Not Set', value: 'Not Set' },
									{ name: 'Risk Accepted', value: 'Risk Accepted' },
									{ name: 'Closed', value: 'Closed' },
									{ name: 'Mitigated', value: 'Mitigated' },
									{ name: 'Remediated', value: 'Remediated' },
									{ name: 'False Positive', value: 'False Positive' },
								],
								default: 'Not Set',
								description: 'The disposition to set',
							},
							{
								displayName: 'Priority',
								name: 'priority',
								type: 'options',
								options: [
									{ name: 'Now', value: 'Now' },
									{ name: 'Next', value: 'Next' },
									{ name: 'Never', value: 'Never' },
								],
								default: 'Next',
								description: 'The priority to set',
							},
							{
								displayName: 'Reason',
								name: 'reason',
								type: 'string',
								default: '',
								required: true,
								description: 'The reason for the update',
							},
						],
					},
				],
			},

			// Group By for stats
			{
				displayName: 'Group By Fields',
				name: 'groupBys',
				type: 'fixedCollection',
				typeOptions: {
					multipleValues: true,
				},
				displayOptions: {
					show: {
						resource: ['vulnerability', 'vulnerabilityDetection', 'asset'],
						operation: ['getStats'],
					},
				},
				default: {},
				options: [
					{
						name: 'groupBy',
						displayName: 'Group By',
						values: [
							{
								displayName: 'Field',
								name: 'field',
								type: 'string',
								default: '',
								required: true,
								description: 'Field to group by',
							},
							{
								displayName: 'Interval',
								name: 'interval',
								type: 'options',
								options: [
									{ name: 'None', value: '' },
									{ name: 'CVSS', value: 'CVSS' },
									{ name: 'Age', value: 'AGE' },
									{ name: 'Minute', value: 'MIN' },
									{ name: 'Hour', value: 'HOUR' },
									{ name: 'Day', value: 'DAY' },
									{ name: 'Week', value: 'WEEK' },
									{ name: 'Month', value: 'MONTH' },
									{ name: 'Year', value: 'YEAR' },
								],
								default: '',
								description: 'Interval to bucket groups (for histograms)',
							},
						],
					},
				],
			},

			// ========== Data Import Job Parameters ==========

			{
				displayName: 'Job ID',
				name: 'jobId',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['job'],
						operation: ['get', 'continue', 'stop', 'delete'],
					},
				},
				default: '',
				required: true,
				description: 'The UUID of the data import job',
			},

			{
				displayName: 'Job Type',
				name: 'jobType',
				type: 'options',
				displayOptions: {
					show: {
						resource: ['job'],
						operation: ['create'],
					},
				},
				options: [
					{ name: 'Asset', value: 'ASSET' },
					{ name: 'SBOM', value: 'SBOM' },
					{ name: 'Unstructured', value: 'UNSTRUCTURED' },
				],
				default: 'ASSET',
				required: true,
				description: 'The type of import job',
			},

			{
				displayName: 'Parser ID',
				name: 'parserId',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['job'],
						operation: ['create'],
					},
				},
				default: '',
				required: true,
				description: 'The UUID of the parser to use',
			},

			{
				displayName: 'Network ID',
				name: 'networkId',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['job'],
						operation: ['create'],
					},
				},
				default: '',
				required: true,
				description: 'The ID of the network',
			},

			{
				displayName: 'Confidence',
				name: 'confidence',
				type: 'number',
				displayOptions: {
					show: {
						resource: ['job'],
						operation: ['create'],
					},
				},
				typeOptions: {
					minValue: 1,
					maxValue: 255,
				},
				default: 60,
				required: true,
				description: 'Confidence setting for import data observations (1-255)',
			},

			{
				displayName: 'Additional Fields',
				name: 'jobAdditionalFields',
				type: 'collection',
				placeholder: 'Add Field',
				displayOptions: {
					show: {
						resource: ['job'],
						operation: ['create'],
					},
				},
				default: {},
				options: [
					{
						displayName: 'Name',
						name: 'name',
						type: 'string',
						default: '',
						description: 'Name of the job',
					},
					{
						displayName: 'Description',
						name: 'description',
						type: 'string',
						default: '',
						description: 'Description of the job',
					},
					{
						displayName: 'Observer',
						name: 'observer',
						type: 'string',
						default: '',
						description: 'Observer/source name',
					},
					{
						displayName: 'Preview',
						name: 'preview',
						type: 'boolean',
						default: false,
						description: 'Whether to stop for preview after enrichment',
					},
					{
						displayName: 'Create New Assets',
						name: 'create_new_assets',
						type: 'boolean',
						default: false,
						description: 'Whether to create new assets when no match is found',
					},
					{
						displayName: 'Retention (Hours)',
						name: 'retention',
						type: 'number',
						default: 48,
						description: 'Hours to keep job files and outputs',
					},
				],
			},

			{
				displayName: 'Step',
				name: 'stepId',
				type: 'options',
				displayOptions: {
					show: {
						resource: ['job'],
						operation: ['continue'],
					},
				},
				options: [
					{ name: 'Parse', value: 'PARSE' },
					{ name: 'Map', value: 'MAP' },
					{ name: 'Enrich', value: 'ENRICH' },
					{ name: 'Associate', value: 'ASSOC' },
					{ name: 'Associate Software', value: 'ASSOC_SOFT' },
					{ name: 'Import', value: 'IMPORT' },
				],
				default: 'PARSE',
				description: 'The step to continue from',
			},

			// ========== Zone Parameters ==========

			{
				displayName: 'Zone ID',
				name: 'zoneId',
				type: 'number',
				displayOptions: {
					show: {
						resource: ['zone'],
						operation: ['get', 'update', 'delete'],
					},
				},
				default: 0,
				required: true,
				description: 'The ID of the zone',
			},

			{
				displayName: 'Zone Name',
				name: 'zoneName',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['zone'],
						operation: ['create', 'update'],
					},
				},
				default: '',
				required: true,
				description: 'The name of the zone',
			},

			{
				displayName: 'Zone Fields',
				name: 'zoneFields',
				type: 'collection',
				placeholder: 'Add Field',
				displayOptions: {
					show: {
						resource: ['zone'],
						operation: ['create', 'update'],
					},
				},
				default: {},
				options: [
					{
						displayName: 'Description',
						name: 'description',
						type: 'string',
						default: '',
						description: 'Description of the zone',
					},
					{
						displayName: 'Color (Hex)',
						name: 'colorHex',
						type: 'string',
						default: '#000000',
						description: 'Color of the zone in hex format',
					},
					{
						displayName: 'Group Label',
						name: 'groupLabel',
						type: 'string',
						default: '',
						description: 'Group label for the zone',
					},
				],
			},

			// ========== Additional Options ==========

			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				options: [
					{
						displayName: 'Sort Field',
						name: 'sortField',
						type: 'string',
						default: '',
						description: 'Field to sort by',
					},
					{
						displayName: 'Sort Descending',
						name: 'sortDescending',
						type: 'boolean',
						default: false,
						description: 'Whether to sort in descending order',
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const resource = this.getNodeParameter('resource', 0) as string;
		const operation = this.getNodeParameter('operation', 0) as string;
		const credentials = await this.getCredentials('dragosApi');
		const baseUrl = credentials.baseUrl as string;

		for (let i = 0; i < items.length; i++) {
			try {
				let responseData: IDataObject | IDataObject[];

				if (resource === 'asset') {
					responseData = await executeAssetOperation(this, i, operation, baseUrl);
				} else if (resource === 'notification') {
					responseData = await executeNotificationOperation(this, i, operation, baseUrl);
				} else if (resource === 'vulnerability') {
					responseData = await executeVulnerabilityOperation(this, i, operation, baseUrl);
				} else if (resource === 'vulnerabilityDetection') {
					responseData = await executeVulnerabilityDetectionOperation(this, i, operation, baseUrl);
				} else if (resource === 'job') {
					responseData = await executeJobOperation(this, i, operation, baseUrl);
				} else if (resource === 'zone') {
					responseData = await executeZoneOperation(this, i, operation, baseUrl);
				} else {
					throw new NodeOperationError(this.getNode(), `Unknown resource: ${resource}`);
				}

				const executionData = this.helpers.constructExecutionMetaData(
					this.helpers.returnJsonArray(responseData),
					{ itemData: { item: i } },
				);
				returnData.push(...executionData);
			} catch (error) {
				if (this.continueOnFail()) {
					const executionData = this.helpers.constructExecutionMetaData(
						this.helpers.returnJsonArray({ error: (error as Error).message }),
						{ itemData: { item: i } },
					);
					returnData.push(...executionData);
					continue;
				}
				throw error;
			}
		}

		return [returnData];
	}
}
