# Ethereum Account Balance Retrieval

This project is a simple Node.js application that allows users to retrieve the balance of an Ethereum account using the `web3.js` library.

## Features

- Retrieve Ethereum account balance using `web3.js`
- Simple Express.js server for handling HTTP requests
- Error handling for invalid Ethereum addresses and connection issues

## Prerequisites

Before running this application, make sure you have the following installed:

- Node.js: [Download and Install Node.js](https://nodejs.org/)
- `npm` (Node Package Manager): This should be installed automatically with Node.js

## Installation

1. Clone the repository to your local machine:

    ```bash
    git clone https://github.com/Sri-shakthi/web.git
    ```

2. Navigate to the project directory:

    ```bash
    cd web
    ```

3. Install dependencies using npm:

    ```bash
    npm install
    ```

## Usage

1. Start the Express server:

    ```bash
    node index.js
    ```

2. Make HTTP requests to retrieve Ethereum account balances:

    ```http
    GET http://localhost:3000/ethbalance/0xYourEthereumAddress
    ```

    Replace `"0xYourEthereumAddress"` with the Ethereum address for which you want to retrieve the balance.

3. The server will respond with the balance of the provided Ethereum address in Ether.

## Configuration

- You can configure the Ethereum node URL in `index.js` by replacing the value of `nodeUrl` with the URL of your Ethereum node provider.

## Contributing

Contributions are welcome! If you find any bugs or have suggestions for improvement, please open an issue or create a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
