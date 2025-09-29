const NoFoosAllowed = require('./rules/no-foos');
const NoBarsAllowed = require('./rules/no-bars');
const UncheckedBlock = require('./rules/unchecked-block');
const ExplicitCast = require('./rules/explicit-cast');
const DeflationaryCheck = require('./rules/deflationary-check');
const InterestingFunctionsAndParameters = require('./rules/interesting-functions-and-parameters');
const CheckReturnValue = require('./rules/check-return-value');
const CallbackNoMsgSenderCheck = require('./rules/callback-no-msgsender-check');


const DumpAST = require('./rules/dump-ast');

module.exports = [
  NoFoosAllowed,
  NoBarsAllowed,
  UncheckedBlock,
  ExplicitCast,
  DeflationaryCheck,
  InterestingFunctionsAndParameters,
  CheckReturnValue,
  DumpAST,
  CallbackNoMsgSenderCheck
]