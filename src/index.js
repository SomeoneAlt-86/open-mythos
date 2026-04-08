'use strict';

module.exports = {
  runPipeline: require('./open-mythos').runPipeline,
  runRecon:    require('./recon').main,
  runTargets:  require('./targets').main,
  runResearch: require('./research').main,
  startServer: require('./server').start,
  openDatabase: require('./db').openDatabase,
  DEFAULT_DB_PATH: require('./db').DEFAULT_DB_PATH,
};
