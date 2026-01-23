module.exports = (on, config) => {
  on('task', {
    GetFromMemories(key) {
      const answers = {
        geoStalkingMetaSecurityAnswer: 'EXPECTED_ANSWER_1',
        geoStalkingVisualSecurityAnswer: 'EXPECTED_ANSWER_2'
      };
      return answers[key];
    },
    GetFromConfig(key) {
      if (key === 'application.domain') return 'example.com';
      return null;
    }
  });
};
