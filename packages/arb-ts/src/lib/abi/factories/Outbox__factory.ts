/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer } from 'ethers'
import { Provider, TransactionRequest } from '@ethersproject/providers'
import { Contract, ContractFactory, Overrides } from '@ethersproject/contracts'

import type { Outbox } from '../Outbox'

export class Outbox__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer)
  }

  deploy(
    _rollup: string,
    _bridge: string,
    overrides?: Overrides
  ): Promise<Outbox> {
    return super.deploy(_rollup, _bridge, overrides || {}) as Promise<Outbox>
  }
  getDeployTransaction(
    _rollup: string,
    _bridge: string,
    overrides?: Overrides
  ): TransactionRequest {
    return super.getDeployTransaction(_rollup, _bridge, overrides || {})
  }
  attach(address: string): Outbox {
    return super.attach(address) as Outbox
  }
  connect(signer: Signer): Outbox__factory {
    return super.connect(signer) as Outbox__factory
  }
  static connect(address: string, signerOrProvider: Signer | Provider): Outbox {
    return new Contract(address, _abi, signerOrProvider) as Outbox
  }
}

const _abi = [
  {
    inputs: [
      {
        internalType: 'address',
        name: '_rollup',
        type: 'address',
      },
      {
        internalType: 'contract IBridge',
        name: '_bridge',
        type: 'address',
      },
    ],
    stateMutability: 'nonpayable',
    type: 'constructor',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'uint256',
        name: 'batchNum',
        type: 'uint256',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'outboxIndex',
        type: 'uint256',
      },
      {
        indexed: false,
        internalType: 'bytes32',
        name: 'outputRoot',
        type: 'bytes32',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'numInBatch',
        type: 'uint256',
      },
    ],
    name: 'OutboxEntryCreated',
    type: 'event',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'l2Sender',
        type: 'address',
      },
      {
        internalType: 'address',
        name: 'destAddr',
        type: 'address',
      },
      {
        internalType: 'uint256',
        name: 'l2Block',
        type: 'uint256',
      },
      {
        internalType: 'uint256',
        name: 'l1Block',
        type: 'uint256',
      },
      {
        internalType: 'uint256',
        name: 'l2Timestamp',
        type: 'uint256',
      },
      {
        internalType: 'uint256',
        name: 'amount',
        type: 'uint256',
      },
      {
        internalType: 'bytes',
        name: 'calldataForL1',
        type: 'bytes',
      },
    ],
    name: 'calculateItemHash',
    outputs: [
      {
        internalType: 'bytes32',
        name: '',
        type: 'bytes32',
      },
    ],
    stateMutability: 'pure',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'bytes32[]',
        name: 'proof',
        type: 'bytes32[]',
      },
      {
        internalType: 'uint256',
        name: 'path',
        type: 'uint256',
      },
      {
        internalType: 'bytes32',
        name: 'item',
        type: 'bytes32',
      },
    ],
    name: 'calculateMerkleRoot',
    outputs: [
      {
        internalType: 'bytes32',
        name: '',
        type: 'bytes32',
      },
    ],
    stateMutability: 'pure',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'uint256',
        name: 'outboxIndex',
        type: 'uint256',
      },
      {
        internalType: 'bytes32[]',
        name: 'proof',
        type: 'bytes32[]',
      },
      {
        internalType: 'uint256',
        name: 'index',
        type: 'uint256',
      },
      {
        internalType: 'address',
        name: 'l2Sender',
        type: 'address',
      },
      {
        internalType: 'address',
        name: 'destAddr',
        type: 'address',
      },
      {
        internalType: 'uint256',
        name: 'l2Block',
        type: 'uint256',
      },
      {
        internalType: 'uint256',
        name: 'l1Block',
        type: 'uint256',
      },
      {
        internalType: 'uint256',
        name: 'l2Timestamp',
        type: 'uint256',
      },
      {
        internalType: 'uint256',
        name: 'amount',
        type: 'uint256',
      },
      {
        internalType: 'bytes',
        name: 'calldataForL1',
        type: 'bytes',
      },
    ],
    name: 'executeTransaction',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [],
    name: 'l2ToL1Block',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'l2ToL1EthBlock',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'l2ToL1Sender',
    outputs: [
      {
        internalType: 'address',
        name: '',
        type: 'address',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'l2ToL1Timestamp',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    name: 'outboxes',
    outputs: [
      {
        internalType: 'contract OutboxEntry',
        name: '',
        type: 'address',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'outboxesLength',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'bytes',
        name: 'sendsData',
        type: 'bytes',
      },
      {
        internalType: 'uint256[]',
        name: 'sendLengths',
        type: 'uint256[]',
      },
    ],
    name: 'processOutgoingMessages',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
]

const _bytecode =
  '0x608060405234801561001057600080fd5b5060405161181f38038061181f8339818101604052604081101561003357600080fd5b508051602090910151600080546001600160a01b038085166001600160a01b0319928316179092556001805492841692909116919091179055604051610078906100bd565b604051809103906000f080158015610094573d6000803e3d6000fd5b50600280546001600160a01b0319166001600160a01b0392909216919091179055506100ca9050565b61059a8061128583390190565b6111ac806100d96000396000f3fe608060405234801561001057600080fd5b506004361061009d5760003560e01c806380648b021161006657806380648b02146102635780638515bc6a1461026b5780639c5cfe0b146102735780639f0c04bf1461036f578063b0f305371461040e5761009d565b80627436d3146100a257806305d3efe61461015a5780630c7268471461016257806346547790146102225780636d5161ec1461022a575b600080fd5b610148600480360360608110156100b857600080fd5b810190602081018135600160201b8111156100d257600080fd5b8201836020820111156100e457600080fd5b803590602001918460208302840111600160201b8311171561010557600080fd5b9190808060200260200160405190810160405280939291908181526020018383602002808284376000920191909152509295505082359350505060200135610416565b60408051918252519081900360200190f35b610148610451565b6102206004803603604081101561017857600080fd5b810190602081018135600160201b81111561019257600080fd5b8201836020820111156101a457600080fd5b803590602001918460018302840111600160201b831117156101c557600080fd5b919390929091602081019035600160201b8111156101e257600080fd5b8201836020820111156101f457600080fd5b803590602001918460208302840111600160201b8311171561021557600080fd5b509092509050610457565b005b61014861053e565b6102476004803603602081101561024057600080fd5b503561054d565b604080516001600160a01b039092168252519081900360200190f35b610247610574565b610148610583565b610220600480360361014081101561028a57600080fd5b81359190810190604081016020820135600160201b8111156102ab57600080fd5b8201836020820111156102bd57600080fd5b803590602001918460208302840111600160201b831117156102de57600080fd5b919390928235926001600160a01b03602082013581169360408301359091169260608301359260808101359260a08201359260c08301359261010081019060e00135600160201b81111561033157600080fd5b82018360208201111561034357600080fd5b803590602001918460018302840111600160201b8311171561036457600080fd5b509092509050610599565b610148600480360360e081101561038557600080fd5b6001600160a01b03823581169260208101359091169160408201359160608101359160808201359160a08101359181019060e0810160c0820135600160201b8111156103d057600080fd5b8201836020820111156103e257600080fd5b803590602001918460018302840111600160201b8311171561040357600080fd5b509092509050610710565b6101486107b0565b600061044984848460405160200180828152602001915050604051602081830303815290604052805190602001206107bf565b949350505050565b60035490565b6000546001600160a01b031633146104a4576040805162461bcd60e51b815260206004820152600b60248201526a04f4e4c595f524f4c4c55560ac1b604482015290519081900360640190fd5b806000805b82811015610535576105138783888888868181106104c357fe5b905060200201358601926104d99392919061114e565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525061088d92505050565b84848281811061051f57fe5b60200291909101359290920191506001016104a9565b50505050505050565b6005546001600160801b031690565b6003818154811061055a57fe5b6000918252602090912001546001600160a01b0316905081565b6004546001600160a01b031690565b600554600160801b90046001600160801b031690565b60006105ab8989898989898989610710565b90506105ee8d8d8d808060200260200160405190810160405280939291908181526020018383602002808284376000920191909152508f9250869150610a5f9050565b6004805460058054600680546001600160a01b038f81166001600160a01b03198716179096556001600160801b038c8116600160801b9081028f83166001600160801b0319808816919091178416919091179096558c821695831695909517909255604080516020601f8b01819004810282018101909252898152969095169582841695949093048216939116916106a4918e918b918b908b9081908401838280828437600092019190915250610cbf92505050565b600480546001600160a01b03959095166001600160a01b031990951694909417909355600580546001600160801b03928316600160801b029383166001600160801b03199182161783169390931790556006805491909316911617905550505050505050505050505050565b600060038960601b60601c6001600160a01b03168960601b60601c6001600160a01b0316898989898989604051602001808a60ff1660ff1660f81b815260010189815260200188815260200187815260200186815260200185815260200184815260200183838082843780830192505050995050505050505050505060405160208183030381529060405280519060200120905098975050505050505050565b6006546001600160801b031690565b82516000906101008111156107d357600080fd5b8260005b828110156108835760028606610830578681815181106107f357fe5b6020026020010151826040516020018083815260200182815260200192505050604051602081830303815290604052805190602001209150610875565b8187828151811061083d57fe5b602002602001015160405160200180838152602001828152602001925050506040516020818303038152906040528051906020012091505b6002860495506001016107d7565b5095945050505050565b80516000908290829061089c57fe5b01602001516001600160f81b0319161415610a5c5780516061146108f4576040805162461bcd60e51b815260206004820152600a6024820152690848288be988a9c8ea8960b31b604482015290519081900360640190fd5b600061090782600163ffffffff610edc16565b9050600061091c83602163ffffffff610edc16565b9050600061093184604163ffffffff610edc16565b60025490915060009061094c906001600160a01b0316610f35565b60015460408051633422b05160e11b81526001600160a01b039283166004820152602481018690526044810187905290519293509083169163684560a29160648082019260009290919082900301818387803b1580156109ab57600080fd5b505af11580156109bf573d6000803e3d6000fd5b5050600380546001810182556000919091527fc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b810180546001600160a01b0386166001600160a01b0319909116179055604080518281526020810187905280820188905290519193508792507fe5ccc8d7080a4904b2f4e42d91e8f06b13fe6cb2181ad1fe14644e856b44c131919081900360600190a250505050505b50565b61010083511115610aa8576040805162461bcd60e51b815260206004820152600e60248201526d50524f4f465f544f4f5f4c4f4e4760901b604482015290519081900360640190fd5b825160020a8210610af3576040805162461bcd60e51b815260206004820152601060248201526f1410551217d393d517d352539253505360821b604482015290519081900360640190fd5b6000610b00848484610416565b9050600060038681548110610b1157fe5b6000918252602090912001546001600160a01b0316905080610b66576040805162461bcd60e51b815260206004820152600960248201526809c9ebe9eaaa8849eb60bb1b604482015290519081900360640190fd5b8451604080516020808201889052818301939093528151808203830181526060820183528051908401206084820186905260a48083018290528351808403909101815260c490920190925291820180516001600160e01b03166357d61c0b60e01b17905290610bd9908390600090611061565b816001600160a01b0316635780e4e76040518163ffffffff1660e01b815260040160206040518083038186803b158015610c1257600080fd5b505afa158015610c26573d6000803e3d6000fd5b505050506040513d6020811015610c3c57600080fd5b5051610535576040805160048152602481019091526020810180516001600160e01b031663083197ef60e41b179052610c79908390600090611061565b600060038881548110610c8857fe5b9060005260206000200160006101000a8154816001600160a01b0302191690836001600160a01b0316021790555050505050505050565b600154604051639e5d4c4960e01b81526001600160a01b03858116600483019081526024830186905260606044840181815286516064860152865160009692959490921693639e5d4c49938a938a938a93909160849091019060208501908083838e5b83811015610d3a578181015183820152602001610d22565b50505050905090810190601f168015610d675780820380516001836020036101000a031916815260200191505b50945050505050600060405180830381600087803b158015610d8857600080fd5b505af1158015610d9c573d6000803e3d6000fd5b505050506040513d6000823e601f3d908101601f191682016040908152811015610dc557600080fd5b815160208301805160405192949293830192919084600160201b821115610deb57600080fd5b908301906020820185811115610e0057600080fd5b8251600160201b811182820188101715610e1957600080fd5b82525081516020918201929091019080838360005b83811015610e46578181015183820152602001610e2e565b50505050905090810190601f168015610e735780820380516001836020036101000a031916815260200191505b506040525050509150915081610ed557805115610e935780518082602001fd5b6040805162461bcd60e51b81526020600482015260126024820152711094925111d157d0d0531317d1905253115160721b604482015290519081900360640190fd5b5050505050565b60008160200183511015610f2c576040805162461bcd60e51b815260206004820152601260248201527152656164206f7574206f6620626f756e647360701b604482015290519081900360640190fd5b50016020015190565b6000816001600160a01b0316636f791d296040518163ffffffff1660e01b815260040160206040518083038186803b158015610f7057600080fd5b505afa158015610f84573d6000803e3d6000fd5b505050506040513d6020811015610f9a57600080fd5b505160408051808201909152600c81526b21a627a722afa6a0a9aa22a960a11b6020820152906110485760405162461bcd60e51b81526004018080602001828103825283818151815260200191508051906020019080838360005b8381101561100d578181015183820152602001610ff5565b50505050905090810190601f16801561103a5780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b5061105b826001600160a01b03166110ac565b92915050565b600480546001600160a01b031981169091556001600160a01b0316611087848484610cbf565b600480546001600160a01b0319166001600160a01b0392909216919091179055505050565b6000604051733d602d80600a3d3981f3363d3d373d3d3d363d7360601b81528260601b60148201526e5af43d82803e903d91602b57fd5bf360881b60288201526037816000f09150506001600160a01b038116611149576040805162461bcd60e51b8152602060048201526016602482015275115490cc4c4d8dce8818dc99585d194819985a5b195960521b604482015290519081900360640190fd5b919050565b6000808585111561115d578182fd5b83861115611169578182fd5b505082019391909203915056fea2646970667358221220ee5af686e65e3b8432a8be1837dec17e34dac044e37605bc519fd0211c629e8d64736f6c634300060b0033608060405234801561001057600080fd5b506000805460ff1916600117905561056d8061002d6000396000f3fe608060405234801561001057600080fd5b506004361061006d5760003560e01c80635780e4e71461007257806357d61c0b1461008c578063684560a2146100b15780636f791d29146100e357806383197ef0146100ff5780639db9af8114610107578063ebf0c71714610124575b600080fd5b61007a61012c565b60408051918252519081900360200190f35b6100af600480360360408110156100a257600080fd5b5080359060200135610132565b005b6100af600480360360608110156100c757600080fd5b506001600160a01b038135169060208101359060400135610205565b6100eb6102b5565b604080519115158252519081900360200190f35b6100af6102be565b6100eb6004803603602081101561011d57600080fd5b50356102d1565b61007a6102e6565b60025481565b61013a6102ec565b60008181526003602052604090205460ff161561018e576040805162461bcd60e51b815260206004820152600d60248201526c1053149150511657d4d4115395609a1b604482015290519081900360640190fd5b60015482146101cf576040805162461bcd60e51b815260206004820152600860248201526710905117d493d3d560c21b604482015290519081900360640190fd5b6000818152600360205260409020805460ff19166001179055600280546000190190819055610201576102013361047a565b5050565b60015415610249576040805162461bcd60e51b815260206004820152600c60248201526b1053149150511657d253925560a21b604482015290519081900360640190fd5b81610286576040805162461bcd60e51b815260206004820152600860248201526710905117d493d3d560c21b604482015290519081900360640190fd5b600080546001600160a01b0390941661010002610100600160a81b031990941693909317909255600155600255565b60005460ff1690565b6102c66102ec565b6102cf3361047a565b565b60036020526000908152604090205460ff1681565b60015481565b60005461010090046001600160a01b0316331461033e576040805162461bcd60e51b815260206004820152600b60248201526a4f4e4c595f42524944474560a81b604482015290519081900360640190fd5b60006001600160a01b0316600060019054906101000a90046001600160a01b03166001600160a01b031663ab5d89436040518163ffffffff1660e01b815260040160206040518083038186803b15801561039757600080fd5b505afa1580156103ab573d6000803e3d6000fd5b505050506040513d60208110156103c157600080fd5b505160408051634032458160e11b815290516001600160a01b03909216916380648b0291600480820192602092909190829003018186803b15801561040557600080fd5b505afa158015610419573d6000803e3d6000fd5b505050506040513d602081101561042f57600080fd5b50516001600160a01b0316146102cf576040805162461bcd60e51b815260206004820152600b60248201526a4f4e4c595f53595354454d60a81b604482015290519081900360640190fd5b6000546040805180820190915260098152684e4f545f434c4f4e4560b81b60208201529060ff161561052a5760405162461bcd60e51b81526004018080602001828103825283818151815260200191508051906020019080838360005b838110156104ef5781810151838201526020016104d7565b50505050905090810190601f16801561051c5780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b50806001600160a01b0316fffea264697066735822122054c6fb3580a82c6fdcc09f0ea57d788d5cbb61c2f625b16058c4e13c6133a57864736f6c634300060b0033'
