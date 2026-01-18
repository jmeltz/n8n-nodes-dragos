import {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class DragosApi implements ICredentialType {
	name = 'dragosApi';
	displayName = 'Dragos API';
	documentationUrl = 'https://portal.dragos.com/api/docs';
	properties: INodeProperties[] = [
		{
			displayName: 'Base URL',
			name: 'baseUrl',
			type: 'string',
			default: 'https://portal.dragos.com',
			placeholder: 'https://your-dragos-instance.com',
			description: 'The base URL of your Dragos instance',
		},
		{
			displayName: 'API Key ID',
			name: 'apiKeyId',
			type: 'string',
			default: '',
			description: 'The API Key ID for authentication',
		},
		{
			displayName: 'API Key Secret',
			name: 'apiKeySecret',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			description: 'The API Key Secret for authentication',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				'API-Key': '={{$credentials.apiKeyId}}',
				'API-Secret': '={{$credentials.apiKeySecret}}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.baseUrl}}',
			url: '/api/v1/authProvider',
			method: 'GET',
		},
	};
}
