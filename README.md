# wallet connect sdk in rust [WIP]

> this is an unofficial implementation

checkout [examples](./examples) to see how it works.

## features support

- [x] estabilish connection with dapp
- [x] watch for requests like tx or message signing and respond
- [ ] estabilish connection with wallet
- [ ] make requests to perform actions

## rpc method support

- [x] wc_sessionPropose
- [x] wc_sessionSettle
- [ ] wc_sessionAuthenticate
- [x] wc_sessionRequest
- [ ] wc_sessionUpdate
- [ ] wc_sessionExtend
- [x] wc_sessionPing
- [ ] wc_sessionDelete
- [ ] wc_sessionEvent

## used by 

- [gm](https://github.com/zemse/gm)