'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up (queryInterface, Sequelize) {
    await queryInterface.addColumn("model_voters", "election_id", {
      type: Sequelize.DataTypes.INTEGER,
    });

    await queryInterface.addConstraint("model_voters", {
      fields: ["election_id"],
      type: "foreign key",
      references: {
        table: "model_elections",
        field: "id",
      },
    });
    /**
     * Add altering commands here.
     *
     * Example:
     * await queryInterface.createTable('users', { id: Sequelize.INTEGER });
     */
  },

  async down (queryInterface, Sequelize) {
    /**
     * Add reverting commands here.
     *
     * Example:
     * await queryInterface.dropTable('users');
     */
    await queryInterface.removeColumn("model_voters", "election_id");
  }
};
