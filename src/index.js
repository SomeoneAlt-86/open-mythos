'use strict';

module.exports = {
  runPipeline: require('./open-mythos').runPipeline,
  runRecon:    require('./recon').main,
  runTargets:  require('./targets').main,
  runResearch: require('./research').main,
  openDatabase: require('./db').openDatabase,
};
